from fakeapt import LocalRepo, Repo, RepoSet
import os
import subprocess
import shutil
import time

# Anything other than / wasnt tested
BOOTSTRAP_DST = '/'

# /var/lib/dpkg is symlink to /Library/dpkg
DPKG_IN_LIBRARY = True

# Packages to include in bootstrap
BASE_PKGS = [
    'base',
    'profile.d',
    'cydia',
    'berkeleydb',
    'openssh',
]

# XXX make some VirtualRepo instead of LocalRepo(Virtual) shit
# NOT ADDED TO sources.list.d
REPOS = [
    [Repo, 'http://apt.saurik.com/', 'ios', 'main'],
    [Repo, 'https://electrarepo64.coolstar.org/'],
    [LocalRepo, 'Virtual'],
]

# Output directory. Creates strap & strap.tgz in it
OUT_DIR = 'bootstrap'

# Mark installed instead of unpacked
MARK_INSTALLED = False

class Utils:
    @classmethod
    def extract_deb_ctl(cls, path, to):
        cls.get_cmd_output(['dpkg-deb', '-e', path, to])

    @classmethod
    def extract_deb_and_get_contents(cls, path_to_deb, extract_to):
        output = cls.get_cmd_output(['dpkg-deb', '-X', path_to_deb, extract_to])

        ret = list()

        for p in output.split('\n'):
            if not p:
                continue
            # for some reason dpkg on iOS generates no
            # trailing slashes for .list's, but dpkg-deb 
            # on mac does
            if p[-1] == '/':
                p = p[:-1]
            if p.startswith('./'):
                p = p[2:]
            p = BOOTSTRAP_DST + p
            ret.append(p)

        ret.sort()

        return ret

    @classmethod
    def gen_pkg_deb_path(cls, pkg):
        return os.path.join('debs', pkg.name + '.deb')

    @classmethod
    def get_cmd_output(cls, args, capture_stderr=False, shell=False):
        return subprocess.check_output(
            args,
            stderr=subprocess.STDOUT if capture_stderr else None,
            shell=shell
        ).decode()

    @classmethod
    def rm_rf(cls, path):
        if isinstance(path, (list, tuple, set)):
            for x in path:
                cls.rm_rf(x)
        else:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            elif os.path.exists(path):
                os.remove(path)
        

if __name__ == '__main__':
    if os.getuid() != 0:
        print('Warning: uid != 0 (You better run me with fakeroot)')

    print('Loading repos')

    repos = RepoSet([x[0](*x[1:]) for x in REPOS])

    print('Building deplist')
    allpkgs = repos.satisfy_reqs_n_deps(BASE_PKGS)

    if not os.path.isdir(OUT_DIR):
        os.mkdir(OUT_DIR)
        os.chdir(OUT_DIR)
    else:
        os.chdir(OUT_DIR)
        print('Removing leftovers (except debs)')
        if os.path.isdir('strap') or os.path.isfile('strap.tgz'):
            print('Found old bootstrap. You have 3 seconds to cancel.')
            time.sleep(3)
        Utils.rm_rf(['ctrls', 'dpkg-lists', 'strap', 'strap.tgz'])

    print('> cd %s' % OUT_DIR)

    print('Downloading debs')
    if not os.path.isdir('debs'):
        os.mkdir('debs')
    for pkg in allpkgs:
        if pkg.filename:
            deb_path = Utils.gen_pkg_deb_path(pkg)

            if os.path.isfile(deb_path):
                if pkg._check_integrity(deb_path)[0]:
                    print('{}: Already downloaded'.format(pkg.name))
                    continue
                else:
                    print('{} changed, redownloading!'.format(pkg.name))

            pkg.download(deb_path)

    os.mkdir('dpkg-lists')
    print('Generating deb content list files & extracting debs')
    for pkg in allpkgs:
        print('\t', pkg.name, end='\n\t\t')
        deb_path = Utils.gen_pkg_deb_path(pkg)
        if not os.path.isfile(deb_path):
            print('[virtual]', end='\n\t\t')
            lst = ['/.']
        else:
            lst = Utils.extract_deb_and_get_contents(deb_path, 'strap')
        
        print('\n\t\t'.join(lst))

        lst_path = os.path.join('dpkg-lists', pkg.name + '.list')
        with open(lst_path, 'w') as f:
            f.write('\n'.join(lst))
            f.write('\n')
        print('\t\t -> wrote to {}'.format(lst_path))

    print('Fixing /etc & /var & /tmp')
    if not os.path.isdir(os.path.join('strap', 'private')):
        os.mkdir(os.path.join('strap', 'private'))
    os.rename(os.path.join('strap', 'etc'), os.path.join('strap', 'private', 'etc'))
    os.rename(os.path.join('strap', 'var'), os.path.join('strap', 'private', 'var'))
    os.symlink(os.path.join('private', 'etc'), os.path.join('strap', 'etc'))
    os.symlink(os.path.join('private', 'var'), os.path.join('strap', 'var'))

    if os.path.exists(os.path.join('strap', 'tmp')):
        os.rmdir(os.path.join('strap', 'tmp'))

    dpkg_dir_path = os.path.join('strap', 'private', 'var', 'lib', 'dpkg')
    if DPKG_IN_LIBRARY:
        print('Applying DPKG_IN_LIBRARY')
        varlib_path = dpkg_dir_path
        library_path = os.path.join('strap', 'Library', 'dpkg')
        
        print('\tMoving dpkg dir to /Library')
        os.rename(varlib_path, library_path)
        
        print('\tCreating /var/lib/dpkg -> /Library/dpkg symlink')
        os.symlink('/Library/dpkg', varlib_path)

        dpkg_dir_path = os.path.join('strap', 'Library', 'dpkg')

    print('Making dpkg status file')
    for pkg in allpkgs:
        for k in ('Size', 'MD5sum', 'SHA1', 'SHA256', 'Filename'):
            pkg._params.pop(k, None)
        # Unpacked so when unbootstrapped "dpkg --configure -a"
        # can be ran to exec all postinsts
        pkg._params['Status'] = 'install ok unpacked' if not MARK_INSTALLED else 'install ok installed'

    with open(os.path.join(dpkg_dir_path, 'status'), 'w') as f:
        f.write('\n\n'.join(p.asstring() for p in allpkgs))
        # Final newline
        f.write('\n')

    print('Filling dpkg/info')
    dpkg_info_path = os.path.join(dpkg_dir_path, 'info')
    os.mkdir('ctrls')
    for pkg in allpkgs:
        print('\t', pkg.name)
        ctrl_dir = os.path.join('ctrls', pkg.name)
        deb_path = Utils.gen_pkg_deb_path(pkg)
        if not os.path.isfile(deb_path):
            continue

        Utils.extract_deb_ctl(deb_path, ctrl_dir)
        for cf in os.listdir(ctrl_dir):
            if cf == 'control':
                continue
            src = os.path.join(ctrl_dir, cf)
            dst = os.path.join(dpkg_info_path, '.'.join((pkg.name, cf)))

            print('\t\t', src, '->', dst)

            os.rename(src, dst)

    print('Copying dpkg lists')
    for f in os.listdir('dpkg-lists'):
        os.rename(os.path.join('dpkg-lists', f), os.path.join(dpkg_info_path, f))

    print('Cleaning up')
    Utils.rm_rf(['ctrls', 'dpkg-lists'])

    print('Packing strap.tgz')
    straplst = os.listdir('strap')
    os.chdir('strap')
    Utils.get_cmd_output(['gtar', '-zpcf', '../strap.tgz'] + straplst)
    os.chdir('..')
