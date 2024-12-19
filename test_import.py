import sys
import os

# Додаємо шлях до папки 'tailtrace'
sys.path.append(os.path.abspath("C:/Users/Админ/Desktop/TailTrace/tailtrace"))

from sniffer import start_sniffing
print("Імпорт успішний!")