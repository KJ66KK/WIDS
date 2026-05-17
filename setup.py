from setuptools import setup, find_packages

# Read requirements from requirements.txt
with open("requirements.txt") as f:
    required = f.read().splitlines()

setup(
    name="wids",
    version="0.1.0",
    description="Wireless Intrusion Detection & Response System",
    author="Your Name",
    packages=find_packages(),
    py_modules=["run_widrs"], # Include the root script
    install_requires=required,
    entry_points={
        "console_scripts": [
            "wids=run_widrs:main",
        ],
    },
    python_requires=">=3.11",
)
