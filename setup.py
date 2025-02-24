from setuptools import setup, find_packages

setup(
    name="nexusxssmodel", 
    version="2.0.0",
    description="Advanced Cross-Site Scripting Detection Tool",
    author="Jehad Mosa",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.8.4",
        "beautifulsoup4>=4.11.2",
        "requests>=2.28.2",
        "typing-extensions>=4.5.0",
        "colorama>=0.4.6",
        "tqdm>=4.65.0",
        "rich>=13.3.5",
        "python-dotenv>=1.0.0",
        "pydantic>=1.10.7"
    ],
    entry_points={
        'console_scripts': [
            'nexusxss=main:main',
        ],
    }
)
