import h5py as h5
import random
import sys

def shuffle(path, name):
    f = h5.File(path, 'w')
    f.create_dataset(name)
    random.shuffle(f)
    f.close()

if __name__ == '__main__':
    shuffle(sys.argv[1], sys.argv[2])