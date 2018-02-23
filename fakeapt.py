import requests
import shutil
import bz2
import os
import hashlib
import io
from urllib.parse import urlparse
import re
from queue import Queue
import itertools
from functools import reduce

__all__ = [
    'Repo',
    'LocalRepo',
    'RepoSet',
    'Package',
    'PkgReq',
]

class HashTools:
    """ https://stackoverflow.com/a/3431835/5279817 """
    @classmethod
    def hash_bytestr_iter(cls, bytesiter, hasher, ashexstr=False):
        for block in bytesiter:
            hasher.update(block)
        return (hasher.hexdigest() if ashexstr else hasher.digest())

    @classmethod
    def file_as_blockiter(cls, afile, blocksize=0x10000):
        with afile:
            block = afile.read(blocksize)
            while len(block) > 0:
                yield block
                block = afile.read(blocksize)

    @classmethod
    def hash_file(cls, filename, hasher, ashexstr=False):
        with open(filename, 'rb') as f:
            return cls.hash_bytestr_iter(cls.file_as_blockiter(f), hasher, ashexstr)

class Utils:
    @staticmethod
    def download_file(url, local_filename=None):
        if local_filename is None:
            local_filename = url.split('/')[-1]

        print('[*] Downloading %s to %s'%(url, local_filename))

        r = requests.get(url, stream=True)
        with open(local_filename, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

        return local_filename

    @staticmethod
    def asstring_to_dict(asstring):
        ret = dict()
        key = None

        for raws in asstring.split('\n'):
            s = raws.strip()
            if not s:
                continue
            
            # comment
            if raws[0] == '#':
                continue

            if ':' in s:
                key, val = s.split(':', maxsplit=1)
                ret[key] = val.strip()
            else:
                if key is None:
                    raise Exception('Expected `:` on line %s' % raws)

                ret[key] = '\n'.join((ret[key], raws))

        return ret

class DebianVersion:
    EPOCH_REGEX = re.compile(r'^([0-9]*(?=:))?:(.*)')
    def __init__(self, s):
        s = s.strip()

        epoch_match = self.EPOCH_REGEX.match(s)
        if epoch_match:
            self.epoch = int(epoch_match.group(1))
            v = epoch_match.group(2)
        else:
            self.epoch = 0
            v = s

        v = v.rsplit('-', 1)
        self.upstream = v[0]
        self.revision = v[1] if len(v) != 1 else ''

    @staticmethod
    def _char_code(c):
        if len(c) != 1:
            c = c[0]
            
        if c == '~':
            return 0; # tilde sort before anything

        if (ord('a') <= ord(c) <= ord('z')) or (ord('A') <= ord(c) <= ord('Z')):
            return ord(c) - ord('A') + 1

        if c in '.+-':
            return ord(c) + ord('z') + 1

        raise Exception('Unexpected char %s in charcode' % c)

    @classmethod
    def _cmp_vers(cls, l, r):
        alpre = re.compile(r'([^0-9]*)([0-9]*.*)')
        numre = re.compile(r'([0-9]*)([^0-9]*.*)')

        anow = True
        while l and r:
            rgx = alpre if anow else numre

            lm = rgx.match(l)
            rm = rgx.match(r)

            l = lm.group(2)
            r = rm.group(2)

            lg = lm.group(1)
            rg = rm.group(1)

            if lg != rg:
                if anow:
                    for lc, rc in zip(lg, rg):
                        diff = cls._char_code(lc) - cls._char_code(rg)
                        if diff != 0:
                            return diff

                    # tilde is sorted before empty part
                    if len(lg) > len(rg):
                        return -1 if lg[len(rg)] == '~' else +1
                    elif len(lg) < len(rg):
                        return +1 if rg[len(lg)] == '~' else -1
                else:
                    diff = int(lg) - int(rg)
                    if diff != 0:
                        return diff

            anow = not anow

        if l or r:
            if len(l) > len(r):
                return -1 if l[len(r)] == '~' else +1
            elif len(l) < len(r):
                return +1 if r[len(l)] == '~' else -1

        return 0

    def _cmp(self, other):
        diff = self.epoch - other.epoch
        diff = self._cmp_vers(self.upstream, other.upstream) if diff == 0 else diff
        diff = self._cmp_vers(self.revision, other.revision) if diff == 0 else diff
        return (1 if diff > 0 else -1) if diff != 0 else 0

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._cmp(other) == 0

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._cmp(other) != 0

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._cmp(other) < 0

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._cmp(other) <= 0

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._cmp(other) > 0

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._cmp(other) >= 0

    def __str__(self):
        vers = self.upstream
        if self.revision:
            vers = '-'.join((vers, self.revision))
        if self.epoch:
            vers = ':'.join((str(self.epoch), vers))
        
        return vers

    def __repr__(self):
        return '<epoch={} upstream={} revision={}>'.format(self.epoch, self.upstream, self.revision)

    def __hash__(self):
        return hash(str(self))

class VersionReq:
    OPS = {
        '>>': (1,),
        '<<': (-1,),
        '==': (0,),
        '!=': (-1, 1),
        '>=': (0, 1),
        '<=': (-1, 0),
    }

    def __init__(self, s):
        s = s.strip()

        # hack for firmware
        if s.startswith('firmware'):
            s = s[len('firmware'):].strip()

        op = s[:2]

        # dirty hack for one char variants
        if op[0] in '<=>' and op[1] not in '<=>':
            op = op[0]

        self.vers = DebianVersion(s[len(op):])

        if len(op) == 1:
            op = op + op

        if op not in self.OPS:
            raise ValueError('invalid op: %s' % op)

        self.op = op
        self.possibilities = self.OPS[self.op]

    def satisfied_by(self, vers):
        if not isinstance(vers, self.vers.__class__):
            vers = self.vers.__class__(vers)

        return vers._cmp(self.vers) in self.possibilities

    def __repr__(self):
        return '{} {}'.format(self.op, str(self.vers))

class PkgReq:
    def __init__(self, s):
        s = s.strip()
        self._subreqs = set(SubPkgReq(sub) for sub in s.split('|'))
        self.names = set(sr.name for sr in self._subreqs)

    def satisfied_by(self, pkg, exact=False):
        for req in self._subreqs:
            if req.satisfied_by(pkg, exact):
                return True

        return False

    def __repr__(self):
        return '<{}>'.format(' | '.join(map(repr, self._subreqs)))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._subreqs == other._subreqs

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._subreqs != other._subreqs

    def __hash__(self):
        return reduce(lambda x, y: x ^ hash(y), self._subreqs, 0)

class SubPkgReq:
    def __init__(self, s):
        name = s.strip()

        vers_match = re.match(r'(.*) \((.*)\)', s)

        if vers_match:
            self.name = vers_match.group(1).strip()
            self.version_req = VersionReq(vers_match.group(2))
        else:
            self.name = name
            self.version_req = None

    def satisfied_by(self, pkg, exact=False):
        if self.name != pkg.name and (exact or self.name not in pkg.provides):
            return False

        if self.version_req:
            return self.version_req.satisfied_by(pkg.version)

        return True

    def __repr__(self):
        return '{}{}'.format(self.name, ' ({})'.format(self.version_req) if self.version_req else '')

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.name == other.name and self.version_req == other.version_req

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.name != other.name or self.version_req != other.version_req

    def __hash__(self):
        return hash(self.name) ^ hash(self.version_req)

class Package:
    def __init__(self, asstring, repo=None):
        self._params = Utils.asstring_to_dict(asstring)
        self.repo = repo

        self.name = self._params['Package']
        self.version = DebianVersion(self._params['Version'])

        self.filename = self._params.get('Filename')

        self.provides = set()
        for s in self._params.get('Provides', '').split(','):
            s = s.strip()
            if s:
                self.provides.add(s.strip())

        def get_csv_param(key):
            for s in self._params.get(key, '').strip().split(','):
                s = s.strip()
                if s:
                    yield s

        self.depends = set()
        for s in itertools.chain(get_csv_param('Depends'), get_csv_param('Pre-Depends')):
            try:
                self.depends.add(PkgReq(s))
            except ValueError:
                print('Fail on %s: dep %s' % (self, s))
                raise

        self.conflicts = set()
        for s in get_csv_param('Conflicts'):
            try:
                self.conflicts.add(PkgReq(s))
            except ValueError:
                print('Fail on %s: conf %s' % (self, s))
                raise

        self.integrity = {
            'size': int(self._params.get('Size', 0)) or None,
            'md5': self._params.get('MD5sum'),
            'sha1': self._params.get('SHA1'),
            'sha256': self._params.get('SHA256'),
        }

    def download(self, saveto=None):
        if self.repo is None or self.filename is None:
            raise Exception('Filename/Repo is None, cant download')
        fname = Utils.download_file(self.repo.relative_url(self.filename), local_filename=saveto)

        integ = self._check_integrity(fname)
        if not integ[0]:
            os.remove(fname)
            raise Exception('integrity error: %s' % integ[1])

        return fname

    def _check_integrity(self, fname):
        try:
            for k, v in self.integrity.items():
                if v is None:
                    continue

                if k == 'size':
                    act_size = os.path.getsize(fname)
                    if act_size != v:
                        raise Exception('integrity error: Expected size %d, got %d' % (v, act_size))
                elif k in ('md5', 'sha1', 'sha256'):
                    if k == 'md5':
                        hasher = hashlib.md5()
                    elif k == 'sha1':
                        hasher = hashlib.sha1()
                    elif k == 'sha256':
                        hasher = hashlib.sha256()

                    vupper = v.upper()
                    act_v = HashTools.hash_file(fname, hasher, ashexstr=True).upper()

                    if vupper != act_v:
                        raise Exception('integrity error: Expected hash %s to be %s, got %s' % (k, vupper, act_v))
                else:
                    raise Exception('unknown integrity check type: %s' % k)
        except Exception as e:
            return False, ' '.join(e.args)

        return True, 'ok'

    def __repr__(self):
        return '<Package {} v{}{}>'.format(
            self.name,
            self.version,
            (' (from %s)' % str(self.repo)) if self.repo else ''
        )

    def __eq__(self, other):
        if not isinstance(other, Package):
            return NotImplemented
        return (self.repo == other.repo) and (self.name == other.name) and (self.version == other.version)

    def __ne__(self, other):
        if not isinstance(other, Package):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash(self.name) ^ hash(self.version) ^ hash(self.repo)

    def asstring(self):
        return '\n'.join('{}: {}'.format(k, v) for k, v in self._params.items())

class Repo:
    def __init__(self, url, dist=None, comp=None, arch='iphoneos-arm'):
        self.url = url

        if dist is None:
            release_path = 'Release'
        else:
            release_path = '/'.join(('dists', dist, 'Release'))

        release = self._fetch_relative(release_path, verify=False)
        if release.ok:
            self._release = Utils.asstring_to_dict(release.text)
            self.name = self._release['Origin']
            self.label = self._release.get('Label', self.name)
        else:
            self._release = dict()
            urlparsed = urlparse(self.url)
            self.name = urlparsed.netloc + urlparsed.path
            self.label = self.name

        self._integrity_by_file = dict()

        if 'MD5Sum' in self._release:
            for l in self._release['MD5Sum'].split('\n'):
                l = l.strip()
                if not l:
                    continue

                md5sum, size, name = map(str.strip, l.split())

                self._integrity_by_file[name] = {
                    'size': int(size),
                    'md5': md5sum
                }

        self.packages = list()
        self.packages_by_name = dict()

        if dist is None or comp is None:
            packages_path = 'Packages'
        else:
            packages_path = '/'.join(('dists', dist, comp, 'binary-' + arch, 'Packages'))

        for pkgstr in self._fetch_bz2(packages_path).split('\n\n'):
            if not pkgstr:
                continue
            
            pkg = Package(pkgstr, self)

            self.packages.append(pkg)

            if pkg.name in self.packages_by_name:
                # print('warning: duplicate package %s' % pkg, end=' -- ')

                prevpkg = self.packages_by_name[pkg.name]
                if pkg.version > prevpkg.version:
                    # print('overriding prev (%s) since prev is older' % prevpkg)
                    self.packages_by_name[pkg.name] = pkg
                else:
                    pass
                    # print('not overriding prev (%s) since prev is newer' % prevpkg)
            else:
                self.packages_by_name[pkg.name] = pkg

    def _fetch(self, url):
        return requests.get(url, stream=True)

    def _fetch_relative(self, uri, verify=True):
        url = self.relative_url(uri)
        r = self._fetch(url)

        if r.ok and verify:
            integ = self._integrity_by_file.get(uri)
            if integ:
                
                if 'size' in integ:
                    act_size = len(r.content)
                    exp_size = integ['size']
                    if act_size != exp_size:
                        raise Exception('integrity error for %s: expcected size %d, got %d' % (uri, exp_size, act_size))

                if 'md5' in integ:
                    exp_md5 = integ['md5'].upper()
                    act_md5 = HashTools.hash_bytestr_iter(HashTools.file_as_blockiter(io.BytesIO(r.content)), hashlib.md5(), True).upper()

                    if exp_md5 != act_md5:
                        raise Exception('integrity error for %s: Expected md5 %s, got %s' % (uri, exp_md5, act_md5))

        return r

    def _fetch_bz2(self, name):
        r = self._fetch_relative(name + '.bz2')
        if r.ok:
            return bz2.decompress(r.content).decode('utf-8', errors='ignore')

        r = self._fetch_relative(name)
        if r.ok:
            return r.content.decode('utf-8', errors='ignore')

        raise Exception('%s & %s.bz2 are missing' % (name, name))

    def satisfy_req(self, req):
        if not isinstance(req, PkgReq):
            req = PkgReq(req)

        for name in req.names:
            fast = self.packages_by_name.get(name)
            if fast is not None and req.satisfied_by(fast):
                return fast

        for p in self.packages:
            if req.satisfied_by(p):
                return p

        return None

    def relative_url(self, rel):
        return '%s/%s' % (self.url, rel)

    def __repr__(self):
        return '<Repo {} with {} packages>'.format(self.name, len(self.packages))

    def __str__(self):
        return '<{}>'.format(self.label)

    def __eq__(self, other):
        if not isinstance(other, Repo):
            return NotImplemented
        return self.url == other.url

    def __ne__(self, other):
        if not isinstance(other, Repo):
            return NotImplemented
        return self.url != other.url

    def __hash__(self):
        return hash(self.url)

class LocalRepo(Repo):
    class FakeResponse:
        def __init__(self, ok, content=None):
            self.ok = ok
            if content is not None:
                self.content = content
                self.text = content.decode('utf-8', errors='ignore')

    def __init__(self, url, dist=None, comp=None, arch='iphoneos-arm'):
        super().__init__(url, dist, comp, arch)

        self.url = os.path.abspath(self.url)

    def __repr__(self):
        return '<LocalRepo {} with {} packages>'.format(self.name, len(self.packages))

    def _fetch(self, url):
        try:
            with open(url, 'rb') as f:
                return self.FakeResponse(True, f.read())
        except FileNotFoundError:
            return self.FakeResponse(False)


class RepoSet:
    def __init__(self, repos):
        self.repos = set()
        self.packages_by_name = dict()
        self.add_repos(repos)

    def _update_pkgs_by_name(self, new_repos=None, removed_repos=None):
        if new_repos is not None:
            for repo in new_repos:
                for _, pkg in repo.packages_by_name.items():
                    if pkg.name in self.packages_by_name:
                        # print('warning: duplicate package %s' % pkg, end=' -- ')

                        prevpkg = self.packages_by_name[pkg.name]
                        if pkg.version > prevpkg.version:
                            # print('overriding prev (%s) since prev is older' % prevpkg)
                            self.packages_by_name[pkg.name] = pkg
                        else:
                            pass
                            # print('not overriding prev (%s) since prev is newer' % prevpkg)
                    else:
                        self.packages_by_name[pkg.name] = pkg
        
        if removed_repos is not None:
            removed_pkg_names = set()
            for _, pkg in self.packages_by_name.items():
                if pkg.repo in removed_repos:
                    removed_pkg_names.add(pkg.name)

            for n in removed_pkg_names:
                del self.packages_by_name[n]
                p = self.satisfy_req(n)
                if p is not None:
                    self.packages_by_name[n] = p

    def add_repos(self, repos):
        added = set()
        for r in repos:
            if not isinstance(r, Repo):
                r = Repo(r)
            if r not in self.repos:
                added.add(r)
                self.repos.add(r)

        self._update_pkgs_by_name(new_repos=added)

    def remove_repos(self, repos):
        removed = set()
        for r in repos:
            if not isinstance(r, Repo):
                r = Repo(r)
            if r in self.repos:
                removed.add(r)
                self.repos.remove(r)

        self._update_pkgs_by_name(removed_repos=removed)

    def satisfy_req(self, req):
        if not isinstance(req, PkgReq):
            req = PkgReq(req)

        for name in req.names:
            fast = self.packages_by_name.get(name)
            if fast is not None and req.satisfied_by(fast):
                return fast

        bestp = None
        for r in self.repos:
            p = r.satisfy_req(req)
            if p is not None:
                if (bestp is None) or (bestp.version < p.version):
                    bestp = p

        return bestp

    def satisfy_pkg_deps(self, needed_pkg, recursive=False):
        if not isinstance(needed_pkg, Package):
            return TypeError('needed_pkg must be %s' % Package)

        # XXX perform magic woodo on req and not on pkgs to avoid extra lookups
        alldeps = set()
        allreqs = set()

        pkgs = Queue()
        pkgs.put(needed_pkg)

        while not pkgs.empty():
            pkg = pkgs.get()

            for req in pkg.depends:
                if req in allreqs:
                    continue

                allreqs.add(req)
                p = self.satisfy_req(req)

                if p is None:
                    raise Exception('Cant satisfy requirement: %s (for pkg %s)' % (req, pkg.name))

                if p not in alldeps and p != needed_pkg:
                    # print('[ADDED %s] -- because required by %s' % (p, pkg))
                    alldeps.add(p)
                    if recursive:
                        pkgs.put(p)

        conflict = self._pkgset_has_conflicts(alldeps)
        if conflict:
            raise Exception('conflict: {}'.format(conflict))

        return alldeps

    def satisfy_reqs_n_deps(self, reqs):
        if isinstance(reqs, (str, PkgReq)):
            reqs = [reqs]

        requirements = (req if isinstance(req, PkgReq) else PkgReq(req) for req in reqs)

        reqdeps = set(self.satisfy_req(req) for req in requirements)
        deps = set()

        for r in reqdeps:
            deps.update(self.satisfy_pkg_deps(r, recursive=True))

        reqdeps.update(deps)

        conflict = self._pkgset_has_conflicts(reqdeps)
        if conflict:
            raise Exception('conflict: {}'.format(conflict))

        return reqdeps

    @staticmethod
    def _pkgset_has_conflicts(pkgset):
        confs = dict()
        for d in pkgset:
            for c in d.conflicts:
                if c in confs:
                    confs[c] += [d]
                else:
                    confs[c] = [d]

        for conf, pkgs in confs.items():
            for d in pkgset:
                if conf.satisfied_by(d, exact=True):
                    return conf, pkgs

        return None

    def __str__(self):
        return '<RepoSet with %d repos>' % len(self.repos)

    def __repr__(self):
        return '<RepoSet {%s}>' % ', '.join(map(str, self.repos))
