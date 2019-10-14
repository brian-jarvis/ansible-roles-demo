#!/usr/bin/python
class FilterModule(object):
    def filters(self):
        return {
            'convert2systemdprop': self.convert_property_suffix
        }

    def convert_property_suffix(self, raw_value):
        import math

        # check if we have an int, in which case there is nothing to convert
        if isinstance(raw_value, int) or raw_value == "":
            return raw_value

        last_char = raw_value[-1]
        size_converter = {"K": 1, "M": 2, "G": 3, "T": 4}

        if last_char.upper() in size_converter:
            p = int(math.pow(1024, size_converter[last_char.upper()]))
            sz = int(raw_value[:-1]) * p
            return sz
        else:
            return raw_value