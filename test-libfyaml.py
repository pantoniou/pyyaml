#!/usr/bin/env python

if __name__ == '__main__':

    # import the yaml module in the build/lib directory
    import sys, os, distutils.util
    build_lib = 'build/lib'
    build_lib_ext = os.path.join('build', 'lib.{}-{}.{}'.format(distutils.util.get_platform(), *sys.version_info))
    sys.path.insert(0, build_lib)
    sys.path.insert(0, build_lib_ext)

    import yaml._yaml, yaml
    import types, pprint, tempfile, sys, os

    print "libfyaml version:", yaml._yaml.get_version_string()

    obj = yaml.load("""
        - Hesperiidae
        - Papilionidae
        - Apatelodidae
        - Epiplemidae
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj

    obj = yaml.load("""
        foo
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj

    obj = yaml.load("""
        foo: bar
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj
