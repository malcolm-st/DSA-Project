import subprocess
import ctypes

# List of libraries to install
libraries = [
    "tkinter",
    "python-docx",
    "pandas",
    "matplotlib",
    "requests",
    "beautifulsoup4",
    "tqdm",
    "GitPython",
    "pywin32"
]

# To install the libraries
def install_libraries():
    for lib in libraries:
        try:
            subprocess.check_call(["pip", "install", lib])
            print(f"{lib} installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error installing {lib}: {e}")


# Install required libraries for CVE Aggregator
install_libraries()

ctypes.windll.user32.MessageBoxW(0, "Required Dependencies for CVE Aggregator has been successful!", "Success!", 0x40)