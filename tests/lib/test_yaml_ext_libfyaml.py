
import yaml._yaml, yaml
import types, pprint, tempfile, sys, os

yaml.PyBaseLoader = yaml.BaseLoader
yaml.PySafeLoader = yaml.SafeLoader
yaml.PyLoader = yaml.Loader
yaml.PyBaseDumper = yaml.BaseDumper
yaml.PySafeDumper = yaml.SafeDumper
yaml.PyDumper = yaml.Dumper

old_scan = yaml.scan
def new_scan(stream, Loader=yaml.CLoader):
    return old_scan(stream, Loader)

old_parse = yaml.parse
def new_parse(stream, Loader=yaml.CLoader):
    return old_parse(stream, Loader)

old_compose = yaml.compose
def new_compose(stream, Loader=yaml.CLoader):
    return old_compose(stream, Loader)

old_compose_all = yaml.compose_all
def new_compose_all(stream, Loader=yaml.CLoader):
    return old_compose_all(stream, Loader)

old_load = yaml.load
def new_load(stream, Loader=yaml.CLoader):
    return old_load(stream, Loader)

old_load_all = yaml.load_all
def new_load_all(stream, Loader=yaml.CLoader):
    return old_load_all(stream, Loader)

old_safe_load = yaml.safe_load
def new_safe_load(stream):
    return old_load(stream, yaml.CSafeLoader)

old_safe_load_all = yaml.safe_load_all
def new_safe_load_all(stream):
    return old_load_all(stream, yaml.CSafeLoader)

old_emit = yaml.emit
def new_emit(events, stream=None, Dumper=yaml.CDumper, **kwds):
    return old_emit(events, stream, Dumper, **kwds)

old_serialize = yaml.serialize
def new_serialize(node, stream, Dumper=yaml.CDumper, **kwds):
    return old_serialize(node, stream, Dumper, **kwds)

old_serialize_all = yaml.serialize_all
def new_serialize_all(nodes, stream=None, Dumper=yaml.CDumper, **kwds):
    return old_serialize_all(nodes, stream, Dumper, **kwds)

old_dump = yaml.dump
def new_dump(data, stream=None, Dumper=yaml.CDumper, **kwds):
    return old_dump(data, stream, Dumper, **kwds)

old_dump_all = yaml.dump_all
def new_dump_all(documents, stream=None, Dumper=yaml.CDumper, **kwds):
    return old_dump_all(documents, stream, Dumper, **kwds)

old_safe_dump = yaml.safe_dump
def new_safe_dump(data, stream=None, **kwds):
    return old_dump(data, stream, yaml.CSafeDumper, **kwds)

old_safe_dump_all = yaml.safe_dump_all
def new_safe_dump_all(documents, stream=None, **kwds):
    return old_dump_all(documents, stream, yaml.CSafeDumper, **kwds)

def _set_up():
    yaml.BaseLoader = yaml.CBaseLoader
    yaml.SafeLoader = yaml.CSafeLoader
    yaml.Loader = yaml.CLoader
    yaml.BaseDumper = yaml.CBaseDumper
    yaml.SafeDumper = yaml.CSafeDumper
    yaml.Dumper = yaml.CDumper
    yaml.scan = new_scan
    yaml.parse = new_parse
    yaml.compose = new_compose
    yaml.compose_all = new_compose_all
    yaml.load = new_load
    yaml.load_all = new_load_all
    yaml.safe_load = new_safe_load
    yaml.safe_load_all = new_safe_load_all
    yaml.emit = new_emit
    yaml.serialize = new_serialize
    yaml.serialize_all = new_serialize_all
    yaml.dump = new_dump
    yaml.dump_all = new_dump_all
    yaml.safe_dump = new_safe_dump
    yaml.safe_dump_all = new_safe_dump_all

def _tear_down():
    yaml.BaseLoader = yaml.PyBaseLoader
    yaml.SafeLoader = yaml.PySafeLoader
    yaml.Loader = yaml.PyLoader
    yaml.BaseDumper = yaml.PyBaseDumper
    yaml.SafeDumper = yaml.PySafeDumper
    yaml.Dumper = yaml.PyDumper
    yaml.scan = old_scan
    yaml.parse = old_parse
    yaml.compose = old_compose
    yaml.compose_all = old_compose_all
    yaml.load = old_load
    yaml.load_all = old_load_all
    yaml.safe_load = old_safe_load
    yaml.safe_load_all = old_safe_load_all
    yaml.emit = old_emit
    yaml.serialize = old_serialize
    yaml.serialize_all = old_serialize_all
    yaml.dump = old_dump
    yaml.dump_all = old_dump_all
    yaml.safe_dump = old_safe_dump
    yaml.safe_dump_all = old_safe_dump_all

def test_c_version(verbose=True):
    version = yaml._yaml.get_version_string()
    if verbose:
        print yaml._yaml.get_version()
        print yaml._yaml.get_version_string()
    assert ("%s.%s.%s" % yaml._yaml.get_version()) == yaml._yaml.get_version_string(),    \
           (yaml._yaml.get_version(), yaml._yaml.get_version_string())

test_c_version.unittest = [ ]

def test_c_tutorial(verbose=True):
    obj = yaml.load("""
        - Hesperiidae
        - Papilionidae
        - Apatelodidae
        - Epiplemidae
        """, Loader=yaml.CLoader)
    assert (obj != None)
    print obj

test_c_tutorial.unittest = [ ]

if __name__ == '__main__':
    print "FOO"
    import test_appliance
    test_appliance.run(globals())

