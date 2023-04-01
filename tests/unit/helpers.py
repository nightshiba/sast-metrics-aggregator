import os


def read_resource(resource_name):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    resource_path = os.path.join(current_dir, 'resources', resource_name)
    with open(resource_path, 'r') as f:
        return f.read()
