# Joins a list with commas and returns it as a string
# Does nothing if input isn't a string


def joinx(arg):
    ret = arg
    if type(ret) is list:
        ret = (', ').join(arg)
    return ret


class FilterModule(object):

    def filters(self):
        return {
            'joinx': joinx
        }
