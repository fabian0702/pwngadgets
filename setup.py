from setuptools import setup, find_packages

setup(
    name='pwngadgets',
    version='0.1.0',    
    description='A python package which provides helper functions for pwntools',
    author='Loris Hirter',
    license='MIT',
    packages=find_packages(),
    install_requires=['pwntools'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)