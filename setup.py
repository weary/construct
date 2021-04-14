import setuptools

setuptools.setup(
    name="construct",
    version="1.0",
    author="weary",
    description="IRC nickserv/chanserv replacement",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[],
    packages=setuptools.find_packages(),
    entry_points={
        "console_scripts": [
            "construct=construct:main",
        ],
    },
    python_requires=">=3.6",
)
