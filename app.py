import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import tkinter.font as tkfont  # <--- импортируем модуль шрифтов
import json
import os
import ctypes

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # SYSTEM_DPI_AWARE
except Exception:
    pass

FILENAME = "Notes"

current_password = None  # глобальная переменная для пароля


SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 300_000

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
def encrypt_notes(data_str, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # PKCS7 padding
    pad_len = AES.block_size - len(data_str.encode()) % AES.block_size
    padded_data = data_str.encode() + bytes([pad_len] * pad_len)

    encrypted = cipher.encrypt(padded_data)
    result = base64.b64encode(salt + iv + encrypted).decode()
    return result

def decrypt_notes(enc_data_b64, password):
    try:
        raw = base64.b64decode(enc_data_b64)
        salt = raw[:SALT_SIZE]
        iv = raw[SALT_SIZE:SALT_SIZE + IV_SIZE]
        encrypted = raw[SALT_SIZE + IV_SIZE:]
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted)

        # Remove padding
        pad_len = padded_data[-1]
        return padded_data[:-pad_len].decode()
    except Exception:
        return None  # Пароль неверный или файл повреждён



def manage_password():
    global current_password

    is_protected = False
    if os.path.exists(FILENAME):
        with open(FILENAME, "r", encoding="utf-8") as f:
            try:
                first_line = json.loads(f.readline().strip())
                is_protected = first_line.get("set", False)
            except:
                pass

    if is_protected:
        choice = messagebox.askquestion("Пароль", "Изменить пароль?", icon='question')
        if choice == 'yes':
            old_password = simpledialog.askstring("Старый пароль", "Введите старый пароль:", show='*')
            new_password = simpledialog.askstring("Новый пароль", "Введите новый пароль:", show='*')
            if not new_password:
                return
            with open(FILENAME, "r", encoding="utf-8") as f:
                f.readline()  # пропускаем флаг
                encrypted = f.read()
            decrypted = decrypt_notes(encrypted, old_password)
            if decrypted is None:
                messagebox.showerror("Ошибка", "Неверный старый пароль.")
                return
            current_password = new_password
            save_data()
            messagebox.showinfo("Успех", "Пароль изменён.")
        else:
            confirm = messagebox.askyesno("Удаление", "Удалить пароль?")
            if confirm:
                password = simpledialog.askstring("Пароль", "Введите текущий пароль:", show='*')
                with open(FILENAME, "r", encoding="utf-8") as f:
                    f.readline()
                    encrypted = f.read()
                decrypted = decrypt_notes(encrypted, password)
                if decrypted is None:
                    messagebox.showerror("Ошибка", "Неверный пароль.")
                    return
                current_password = None
                try:
                    globals()['data'] = json.loads(decrypted)
                except Exception:
                    messagebox.showerror("Ошибка", "Невозможно расшифровать данные")
                    return
                save_data()
                messagebox.showinfo("Успех", "Пароль удалён.")
    else:
        password = simpledialog.askstring("Установка пароля", "Введите новый пароль:", show='*')
        if not password:
            return
        current_password = password
        save_data()
        messagebox.showinfo("Готово", "Пароль установлен.")











def load_data():
    global current_password
    if not os.path.exists(FILENAME):
        return {}

    with open(FILENAME, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()
        content = f.read()

        try:
            flag = json.loads(first_line)
        except Exception:
            messagebox.showerror("Ошибка", "Первая строка файла повреждена")
            return {}

        if flag.get("set"):
            # файл зашифрован
            while True:
                password = password = custom_password_dialog("Пароль", "Введите пароль:")

                if password is None:
                    root.destroy()
                    exit()
                decrypted = decrypt_notes(content, password)
                if decrypted:
                    try:
                        current_password = password
                        return json.loads(decrypted)
                    except json.JSONDecodeError:
                        messagebox.showerror("Ошибка", "Ошибка данных, попробуйте снова")
                        root.destroy()
                        exit()
                else:
                    retry = messagebox.askretrycancel("Ошибка", "Неверный пароль. Повторить попытку?")
                    if not retry:
                        root.destroy()
                        exit()
        else:
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                messagebox.showerror("Ошибка", "Повреждён файл")
                return {}








def save_data():
    global current_password
    try:
        with open(FILENAME, "w", encoding="utf-8") as f:
            if current_password:
                f.write('{"set": true}\n')
                encrypted = encrypt_notes(json.dumps(data, ensure_ascii=False, indent=4), current_password)
                f.write(encrypted)
            else:
                f.write('{"set": false}\n')
                json.dump(data, f, ensure_ascii=False, indent=4)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось сохранить базу:\n{e}")

        
        
        

def insert_tree_items(parent, node):
 for key, val in node.items():
        if not key:  # пропускаем пустые ключи
            continue
        if isinstance(val, dict):
            item_id = tree.insert(parent, "end", text=key, open=False)
            insert_tree_items(item_id, val)
        else:
            tree.insert(parent, "end", text=key, open=False)

def on_tree_select(event):
    global current_path
    selected = tree.selection()
    if not selected:
        current_path.clear()
        text.config(state="disabled")
        text.delete("1.0", tk.END)
        save_button.config(state="disabled")
        rename_button.config(state="disabled")
        add_folder_button.config(state="normal")
        add_note_button.config(state="normal")
        delete_button.config(state="disabled")
        return
    item = selected[0]
    path = []
    while item:
        path.insert(0, tree.item(item, "text"))
        item = tree.parent(item)
    current_path = path

    node = data
    for p in path[:-1]:
        node = node.get(p, {})
    val = node.get(path[-1])
    if isinstance(val, str):
        text.config(state="normal")
        text.delete(tk.END + " linestart", tk.END)
        text.delete("1.0", tk.END)
        text.insert(tk.END, val)
        save_button.config(state="normal")
        add_folder_button.config(state="disabled")
        add_note_button.config(state="disabled")
        delete_button.config(state="normal")
        rename_button.config(state="normal")
    else:
        text.config(state="disabled")
        text.delete("1.0", tk.END)
        save_button.config(state="disabled")
        add_folder_button.config(state="normal")
        add_note_button.config(state="normal")
        delete_button.config(state="normal")
        rename_button.config(state="normal")

def save_note():
    global current_path
    if not current_path:
        return
    node = data
    for p in current_path[:-1]:
        node = node.setdefault(p, {})
    node[current_path[-1]] = text.get("1.0", tk.END).rstrip("\n")
    save_data()
    messagebox.showinfo("Сохранено", "Заметка сохранена!")

def add_folder():
    global current_path
    if current_path:
        node = data
        for p in current_path:
            node = node.setdefault(p, {})
    else:
        node = data

    folder_name = simpledialog.askstring("Новая папка", "Введите имя папки:")
    if not folder_name:
        return

    folder_name = "📁 " + folder_name  # Добавляем эмодзи в начало имени

    if folder_name in node:
        messagebox.showerror("Ошибка", "Папка с таким именем уже существует")
        return

    node[folder_name] = {}
    save_data()
    refresh_tree()
    messagebox.showinfo("Добавлено", f"Папка '{folder_name}' добавлена")


def add_note():
    global current_path
    if current_path:
        node = data
        for p in current_path:
            node = node.setdefault(p, {})
    else:
        node = data

    note_name = simpledialog.askstring("Новая заметка", "Введите имя заметки:")
    if not note_name:
        return

    if note_name in node:
        messagebox.showerror("Ошибка", "Заметка с таким именем уже существует")
        return

    node[note_name] = ""
    save_data()
    refresh_tree()
    messagebox.showinfo("Добавлено", f"Заметка '{note_name}' добавлена")

def delete_item():
    global current_path
    if not current_path:
        return

    answer = messagebox.askyesno("Удаление", f"Вы действительно хотите удалить '{current_path[-1]}'?")
    if not answer:
        return

    node = data
    for p in current_path[:-1]:
        node = node.get(p, {})

    try:
        del node[current_path[-1]]
    except KeyError:
        messagebox.showerror("Ошибка", "Не удалось найти элемент для удаления")
        return

    save_data()
    refresh_tree()
    messagebox.showinfo("Удалено", "Элемент успешно удалён")

def rename_item():
    global current_path
    if not current_path:
        return

    node = data
    for p in current_path[:-1]:
        node = node.get(p, {})

    old_name = current_path[-1]
    new_name = simpledialog.askstring("Переименование", "Введите новое имя:", initialvalue=old_name)
    if not new_name:
        return

    if new_name == old_name:
        return

    if new_name in node:
        messagebox.showerror("Ошибка", "Элемент с таким именем уже существует")
        return

    # Переименование: перенос значения и удаление старого ключа
    node[new_name] = node.pop(old_name)
    save_data()
    refresh_tree()
    messagebox.showinfo("Переименовано", f"'{old_name}' переименовано в '{new_name}'")

def refresh_tree(current_data=None):
    if current_data is None:
        current_data = data
    tree.delete(*tree.get_children())
    insert_tree_items("", current_data)
    # Остальное без изменений
    text.delete("1.0", tk.END)
    text.config(state="disabled")
    save_button.config(state="disabled")
    add_folder_button.config(state="normal")
    add_note_button.config(state="normal")
    delete_button.config(state="disabled")
    rename_button.config(state="disabled")
    global current_path
    current_path = []








def center_window(root, width, height):
    # Получаем размеры экрана
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    # Вычисляем координаты для размещения окна по центру
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    
    # Устанавливаем размер и позицию окна
    root.geometry(f"{width}x{height}+{x}+{y}")



def custom_password_dialog(title, prompt):
    pw = None

    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.resizable(False, False)
    dialog.configure(bg="#f0f0f0")
    dialog.attributes("-topmost", True)  # всегда поверх
    dialog.grab_set()  # модальность

    # Удаляем стандартную рамку и заголовок
    dialog.overrideredirect(True)

    # Размеры
    w, h = 420, 180
    x = (dialog.winfo_screenwidth() // 2) - (w // 2)
    y = (dialog.winfo_screenheight() // 2) - (h // 2)
    dialog.geometry(f"{w}x{h}+{x}+{y}")

    # Обёртка с рамкой (чтобы выглядело не как "голое" окно)
    outer = tk.Frame(dialog, bg="gray", bd=2)
    outer.pack(expand=True, fill=tk.BOTH)

    container = tk.Frame(outer, bg="white", padx=20, pady=20)
    container.pack(expand=True, fill=tk.BOTH)

    label = tk.Label(container, text=prompt, bg="white", font=("Arial", 10))
    label.pack(pady=(0, 10))

    entry = tk.Entry(container, show="*", font=("Arial", 10), width=30, relief=tk.SOLID, bd=1)
    entry.pack()
    entry.focus()

    def on_ok():
        nonlocal pw
        pw = entry.get()
        dialog.destroy()

    def on_cancel():
        dialog.destroy()

    button_frame = tk.Frame(container, bg="white")
    button_frame.pack(pady=15)

    ok_button = tk.Button(
    button_frame,
    text="ОК",
    command=on_ok,
    font=("Arial", 9, "bold"),  # большой жирный шрифт
    width=10,                   # ширина в символах
    height=2                    # высота в строках текста
    )
    ok_button.pack(side=tk.LEFT, padx=10, pady=5)

    cancel_button = tk.Button(
        button_frame,
        text="Отмена",
        command=on_cancel,
        font=("Arial", 9, "bold"),
        width=10,
        height=2
    )
    cancel_button.pack(side=tk.LEFT, padx=10, pady=5)
    cancel_button.pack(side=tk.LEFT, padx=5)

    dialog.bind("<Return>", lambda event: on_ok())
    dialog.bind("<Escape>", lambda event: on_cancel())

    dialog.wait_window()
    return pw
















# делаем папку неактивной при нажатии на пусом месте
def on_tree_click(event):
    item = tree.identify_row(event.y)
    if not item:
        tree.selection_remove(tree.selection())
        global current_path
        current_path = []
        text.config(state="disabled")
        text.delete("1.0", tk.END)
        save_button.config(state="disabled")
        add_folder_button.config(state="normal")
        add_note_button.config(state="normal")
        delete_button.config(state="disabled")
        rename_button.config(state="disabled")




root = tk.Tk()

root.title("Заметки")
window_width = 850
window_height = 600
center_window(root, window_width, window_height)





# Создаем объект шрифта с нужным размером
default_font = tkfont.Font(family="Arial", size=10)

# Настраиваем стиль для ttk.Treeview, чтобы применить шрифт
style = ttk.Style()
style.configure("Treeview", font=default_font)
style.configure("Treeview", font=default_font, rowheight=30)  # добавил rowheight для увеличения высоты строки
style.configure("Treeview.Heading", font=(default_font.actual("family"), 15))  # например, заголовки чуть больше






# Верхняя панель с кнопками
button_frame = tk.Frame(root)
button_frame.pack(side=tk.TOP, fill=tk.X)

# Кнопки в button_frame
save_button = tk.Button(button_frame, text="Сохранить заметку", command=save_note, state="disabled", font=default_font)
save_button.pack(side=tk.LEFT, padx=5, pady=5)

add_folder_button = tk.Button(button_frame, text="Добавить папку", command=add_folder, font=default_font)
add_folder_button.pack(side=tk.LEFT, padx=5, pady=5)

add_note_button = tk.Button(button_frame, text="Добавить заметку", command=add_note, font=default_font)
add_note_button.pack(side=tk.LEFT, padx=5, pady=5)

delete_button = tk.Button(button_frame, text="Удалить", command=delete_item, state="disabled", font=default_font)
delete_button.pack(side=tk.LEFT, padx=5, pady=5)

rename_button = tk.Button(button_frame, text="Переименовать", command=rename_item, state="disabled", font=default_font)
rename_button.pack(side=tk.LEFT, padx=5, pady=5)

password_button = tk.Button(button_frame, text="🔑 Пароль", command=lambda: manage_password(), font=default_font)
password_button.pack(side=tk.RIGHT, padx=5, pady=5)


# Основной фрейм под дерево и текст, под кнопками
frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

tree = ttk.Treeview(frame, columns=("Name",), show="tree")
tree.pack(side=tk.LEFT, fill=tk.Y)

text_frame = tk.Frame(frame)
text_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Полоса прокрутки
scrollbar = tk.Scrollbar(text_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Текст с привязкой скроллбара
text = tk.Text(text_frame, wrap=tk.WORD, width=50, font=default_font, yscrollcommand=scrollbar.set)
text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Настраиваем полосу прокрутки на управление текстом
scrollbar.config(command=text.yview)


search_var = tk.StringVar()
search_results = []  # список item_id найденных элементов
search_index = -1    # текущий индекс выбранного элемента в поиске

def on_search_change(*args):
    global search_results, search_index
    query = search_var.get().lower()
    search_results = []
    search_index = -1
    if not query:
        refresh_tree()
    else:
        filtered = filter_data(data, query)
        refresh_tree(filtered)
        # Собираем найденные item_id
        def collect_notes(node=""):
            for item in tree.get_children(node):
                if not tree.get_children(item):
                    search_results.append(item)
                else:
                    collect_notes(item)
                    
                    # Подсвечиваем найденные записи зелёным цветом
            for item_id in search_results:
                tree.item(item_id, tags=("found",))
            tree.tag_configure("found", foreground="green")
        collect_notes()
        if search_results:
            search_index = 0
            select_search_result()
            
def select_search_result():
    if 0 <= search_index < len(search_results):
        item = search_results[search_index]
        tree.selection_set(item)
        tree.focus(item)
        tree.see(item)
        on_tree_select(None)


search_var.trace_add("write", on_search_change)
search_frame = tk.Frame(root)
search_frame.pack(fill=tk.X, padx=5, pady=5)
search_label = tk.Label(search_frame, text="Поиск:", font=default_font)
search_label.pack(side=tk.LEFT)
search_entry = tk.Entry(search_frame, textvariable=search_var, font=default_font)
search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
# Кнопки "Назад" и "Вперёд"
prev_button = tk.Button(search_frame, text="<", command=lambda: move_search(-1), font=default_font)
prev_button.pack(side=tk.LEFT, padx=5)
next_button = tk.Button(search_frame, text=">", command=lambda: move_search(1), font=default_font)
next_button.pack(side=tk.LEFT)


def move_search(direction):
    global search_index
    if not search_results:
        return
    search_index = (search_index + direction) % len(search_results)
    select_search_result()


def filter_data(node, query):
    """
    Рекурсивно фильтрует данные по query.
    Возвращает словарь с элементами, где в ключах или в строковых значениях есть query.
    """
    filtered = {}
    for key, val in node.items():
        if isinstance(val, dict):
            # Рекурсивно фильтруем вложенные папки
            filtered_sub = filter_data(val, query)
            if filtered_sub:
                filtered[key] = filtered_sub
            else:
                # Проверим, содержит ли название папки запрос
                if query in key.lower():
                    filtered[key] = val  # добавляем папку целиком
        else:
            # val — текст заметки
            if query in key.lower() or query in val.lower():
                filtered[key] = val
    return filtered


def find_first_note_item(tree_parent=""):
    """
    Рекурсивно ищем первый лист в treeview — заметку.
    """
    children = tree.get_children(tree_parent)
    for child in children:
        # Проверяем — лист ли это (нет ли у него дочерних элементов)
        if not tree.get_children(child):
            return child
        else:
            # Рекурсивно ищем в потомках
            result = find_first_note_item(child)
            if result:
                return result
    return None


data = load_data()
current_path = []
refresh_tree()
tree.bind("<<TreeviewSelect>>", on_tree_select)
tree.bind("<Button-1>", on_tree_click)
root.mainloop()