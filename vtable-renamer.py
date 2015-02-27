import idaapi
import idautils

# Eventually add the other typeinfos
classNames = ['__ZTVN10__cxxabiv117__class_type_infoE', '__ZTVN10__cxxabiv120__si_class_type_infoE']
nModules = idaapi.get_import_module_qty()

_class_type_infoNameOffset = 8

# From toolbag/ida.py
def getString(ea):
    stype = idc.GetStringType(ea)
    return idc.GetString(ea, strtype=stype)

def for_class_type_infoDataRef(typeInfoName, dataRef):
    classInfo = dataRef
    nameAddr = idaapi.get_qword(classInfo + _class_type_infoNameOffset)
    name = getString(nameAddr)
    print('class info @ %s' % hex(classInfo))
    print('class name  (%s): %s' % (hex(nameAddr), name))

    # Find the vtable
    classInfoRefs = []
    for ref in idautils.DataRefsTo(classInfo):
        # Why do we have code refs here, wtf?!
        if isCode(idaapi.getFlags(ref)):
            continue
        # If we're looking at a ptr followed by aligning directive, we're likely to be in an si_class_info
        if isAlign(idaapi.getFlags(ref + 8)):
            continue
        # If we have zeroes after the ref, it might be in an si_class_type's parent field
        if idaapi.get_qword(ref + 8) == 0:
            continue
        print(ref)
        classInfoRefs.append(ref)
    if len(classInfoRefs) != 1:
        print("bailing out. Found more than one ref:")
        for i in classInfoRefs:
            print(hex(i))
        return

    vtableAddr = classInfoRefs[0] + 8
    print('vtable @ %s' % hex(vtableAddr))
    if name:
        idaapi.set_name(vtableAddr, '_ZTV' + name)
        idaapi.set_name(classInfo, '_ZTI' + name)

def perImportName(ea, name, ordinal):
    if name in classNames:
        for xref in idautils.DataRefsTo(ea):
            for_class_type_infoDataRef(name, xref)
    return True

for i in xrange(0, nModules):
    if re.search('libc\+\+', idaapi.get_import_module_name(i)):
        print(idaapi.get_import_module_name(i))
        idaapi.enum_import_names(i, perImportName)
