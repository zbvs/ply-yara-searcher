import platform

os_platform = platform.system()


def normalize_root_path(root_path):
    if os_platform == 'Windows':
        root_path += '\\'
    else:
        if root_path != "./":
            root_path += '/'
    return root_path


def get_extension(path):
    if os_platform == 'Windows':
        index = path.rfind('\\')
    else:
        index = path.rfind('/')
    if index != -1:
        path = path[index + 1:]
    else:
        path = path

    index = path.rfind('.')
    if index == -1:
        return 'default'
    return path[index + 1:]
