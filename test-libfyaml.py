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

    obj = yaml.load("""
        foo: bar
        baz: frooz
        seq: [ 1, 2, 3 ]
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj

    obj = yaml.load("""
        - &foo Hesperiidae
        - *foo
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj

    obj = yaml.load("""
        - Hesperiidae
        - !!str "10"
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj

    obj = yaml.load("""
        boolean: !!bool "true"
        integer: !!int "3"
        float: !!float "3.14"
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj

    document = """
                foo: bar
                "bar":
                  - baz
                  - 1
                test: |
                  literal
               """

    print "scan, python loader"
    tokens = yaml.scan(document, Loader=yaml.Loader)
    for token in tokens:
        print "  ", token

    print "scan, c loader"
    tokens = yaml.scan(document, Loader=yaml.CLoader)
    for token in tokens:
        print "  ", token

    print "parse, python loader"
    events = yaml.parse(document, Loader=yaml.Loader)
    for event in events:
        print "  ", event

    print "parse, c loader"
    events = yaml.parse(document, Loader=yaml.CLoader)
    for event in events:
        print "  ", event

    document = """
        ? |-
          foo
        : |-
          bar
        """

    print "parse, python loader"
    events = yaml.parse(document, Loader=yaml.Loader)
    for event in events:
        print "  ", event

    print "parse, c loader"
    events = yaml.parse(document, Loader=yaml.CLoader)
    for event in events:
        print "  ", event
