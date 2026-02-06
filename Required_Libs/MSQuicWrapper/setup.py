from distutils.core import setup, Extension

setup(name='msquicPkg', version='1.0', \
    ext_modules=[Extension('msquic', ['MSQuicSocket.cpp', 'MSQuicWrapper.cpp'], include_dirs = ['/usr/local/include'], library_dirs=["/usr/local/lib/"], libraries=["msquic"],  runtime_library_dirs=["/usr/local/lib/"], extra_link_args=['-Wl,-rpath,$ORIGIN'])])