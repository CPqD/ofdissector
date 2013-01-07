# This is a very nasty code generator. It will get better someday.

IDENT = " " * 4
OFSPEC = "of13"

class Enum:
    def __init__(self, name, bitmap=False, length=32):
        self.name = name
        self.bitmap = bitmap
        self.lines = []

        # Calc reserved bits
        self.length = length
        self.mask = [0 for x in range(length)]

    def add(self, field, value, desc):
        if current.bitmap:
            try:
                bit = int(value.split("<<")[1].strip())
                current.add_masked_bit(bit)
            except IndexError: # Ignore unshifted things
                return
            
            self.lines.append("BITMAP_PART(\"{0}.{1}\", \"{2}\", {3}, {1});".format(self.name, field, desc, self.length, field));
        else:
            self.lines.append("TYPE_ARRAY_ADD({0}, {1}, \"{2} - {3}\");".format(self.name, field, desc, field))

    def add_masked_bit(self, bit):
        self.mask[bit] = 1

    def get_reserved(self):
        self.mask.reverse()
        result = hex(int("0b" + "".join([str(int(not d)) for d in self.mask]), 2)).strip("L")
        self.mask.reverse()
        return result

    def __str__(self):
        s = "// %s\n" % self.name
        if not self.bitmap:
            s += "TYPE_ARRAY(%s);\n" % self.name
        s += "\n".join(self.lines)
        if self.bitmap:
            s += "\nBITMAP_PART(\"{0}.RESERVED\", \"Reserved\", {1}, {2});".format(self.name, self.length, self.get_reserved())
        return s

f = open(OFSPEC, "r")
lines = [i.strip("\n").split(" / ") for i in f.readlines()]
enums = []

for row in lines:
    if row == [""]:
        continue
    if len(row) == 1:
        name = row[0]
        bitmap = False
        length = 0
        if ("*" in name):
            name, length = name.split("*")
            bitmap = True
            length = int(length)
        enum = Enum(name, bitmap, length)
        enums.append(enum)
        continue

    current = enums[-1]
    field, value, desc = row
    desc = desc.replace("\"", "\\\"")
    current.add(field, value, desc)

for enum in enums:
    if not enum.bitmap:
        print "GArray* %s;" % enum.name

print
print

print "void DissectorContext::setupCodes(void) {"
for enum in enums:
    if not enum.bitmap:
        print IDENT + str(enum).replace("\n", "\n" + IDENT)
        print
print "}"

print
print

print "void DissectorContext::setupFlags(void) {"
for enum in enums:
    if enum.bitmap:
        print IDENT + str(enum).replace("\n", "\n" + IDENT)
        print
print "}"
