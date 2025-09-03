import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor

# Fix path issue when bundled with PyInstaller
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# For resource loading after packaging
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

from redhook_gui import RedHookApp

if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Dark theme
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#111111"))
    palette.setColor(QPalette.WindowText, QColor("#ffffff"))
    app.setPalette(palette)

    # Launch app
    window = RedHookApp()
    window.show()

    sys.exit(app.exec_())
