import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import tkinter.font as tkfont
import json
import os
import ctypes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
from sys import exit
# ==============================================
# ГЛОБАЛЬНЫЕ НАСТРОЙКИ И ПЕРЕМЕННЫЕ
# ==============================================

FILENAME = "Notes"  # Имя файла для хранения данных
current_password = None  # Текущий пароль (если установлен)
is_note_selected = False


# Криптографические настройки
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 50_000

# Настройка DPI для Windows
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # SYSTEM_DPI_AWARE
except Exception:
    pass

# ==============================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С ШИФРОВАНИЕМ
# ==============================================

def derive_key(password, salt):
    """Генерация ключа из пароля и соли с помощью PBKDF2"""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_notes(data_str, password):
    """Шифрование данных с использованием AES-256 в режиме CBC"""
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
    """Дешифрование данных с проверкой пароля"""
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

# ==============================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С ДАННЫМИ
# ==============================================

def load_data():
    """Загрузка данных из файла с проверкой пароля"""
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
                password = custom_password_dialog("Пароль", None)

                if password is None:
                    root.destroy()
                    exit()
                decrypted = decrypt_notes(content, password)
                if decrypted:
                    try:
                        current_password = password
                        
                        # Показать главное окно
                        root.deiconify()
                        
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
    """Сохранение данных в файл с возможным шифрованием"""
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

# ==============================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С ПАРОЛЕМ
# ==============================================

def manage_password():
    """Управление паролем: установка, изменение, удаление"""
    global current_password

    # Проверяем, защищен ли файл паролем
    is_protected = False
    if os.path.exists(FILENAME):
        with open(FILENAME, "r", encoding="utf-8") as f:
            try:
                first_line = json.loads(f.readline().strip())
                is_protected = first_line.get("set", False)
            except:
                pass

    if is_protected:
        # Файл защищен паролем - предлагаем изменить или удалить
        choice = messagebox.askquestion("Пароль", "Изменить пароль?", icon='question')
        if choice == 'yes':
            # Изменение пароля
            old_password = simpledialog.askstring("Старый пароль", "Введите старый пароль:", show='*')
            if not old_password:
                return
            
            new_password = simpledialog.askstring("Новый пароль", "Введите новый пароль:", show='*')
            if not new_password:
                return

            # Подтверждение нового пароля
            confirm_password = simpledialog.askstring("Подтверждение пароля", "Введите новый пароль ещё раз:", show='*')
            if new_password != confirm_password:
                messagebox.showerror("Ошибка", "Пароли не совпадают.")
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
            # Удаление пароля
            confirm = messagebox.askyesno("Удаление", "Удалить пароль?")
            if confirm:
                password = simpledialog.askstring("Пароль", "Введите текущий пароль:", show='*')
                if not password:
                    return
                
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
        # Файл не защищен - устанавливаем пароль
        password = simpledialog.askstring("Установка пароля", "Введите новый пароль:", show='*')
        if not password:
            return
        
        # Подтверждение нового пароля
        confirm_password = simpledialog.askstring("Подтверждение пароля", "Введите новый пароль ещё раз:", show='*')
        if password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return
        
        current_password = password
        save_data()
        messagebox.showinfo("Готово", "Пароль установлен.")

# ==============================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С ИНТЕРФЕЙСОМ
# ==============================================

def center_window(window, width, height, parent=None):
    """Центрирование окна на экране или относительно родительского окна"""
    if parent:
        # Центрирование относительно родительского окна
        parent_x = parent.winfo_x()
        parent_y = parent.winfo_y()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        
        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2
    else:
        # Центрирование на экране (как было раньше)
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
    
    window.geometry(f"{width}x{height}+{x}+{y}")

def custom_password_dialog(title, prompt):
    """Кастомное диалоговое окно для ввода пароля"""
    pw = None

    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.resizable(False, False)
    dialog.configure(bg="#f0f0f0")
    dialog.attributes("-topmost", True)  # всегда поверх
    dialog.grab_set()  # модальность

    root.withdraw()  # Скрыть главное окно
    
    # Удаляем стандартную рамку и заголовок
    dialog.overrideredirect(True)

    # Размеры и позиционирование
    w, h = 420, 250
    x = (dialog.winfo_screenwidth() // 2) - (w // 2)
    y = (dialog.winfo_screenheight() // 2) - (h // 2)
    dialog.geometry(f"{w}x{h}+{x}+{y}")

    # Обёртка с рамкой
    outer = tk.Frame(dialog, bg="gray", bd=2)
    outer.pack(expand=True, fill=tk.BOTH)

    container = tk.Frame(outer, bg="white", padx=20, pady=20)
    container.pack(expand=True, fill=tk.BOTH)


    # Добавим крупный замок
    emoji_label = tk.Label(container, text="🔒", bg="white", font=("Arial", 28))
    emoji_label.pack()

    # Подпись под ним
    text_label = tk.Label(container, text="Введите пароль:", bg="white", font=("Arial", 10))
    text_label.pack(pady=(0, 2))


    label = tk.Label(container, text=prompt, bg="white", font=("Arial", 10))
    label.pack(pady=(0, 2))

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
    button_frame.pack(pady=7)

    ok_button = tk.Button(
        button_frame,
        text="ОК",
        command=on_ok,
        font=("Arial", 9, "bold"),
        width=8,
        height=1
    )
    ok_button.pack(side=tk.LEFT, padx=10, pady=5)

    cancel_button = tk.Button(
        button_frame,
        text="Отмена",
        command=on_cancel,
        font=("Arial", 9, "bold"),
        width=8,
        height=1
    )
    cancel_button.pack(side=tk.LEFT, padx=10, pady=5)

    dialog.bind("<Return>", lambda event: on_ok())
    dialog.bind("<Escape>", lambda event: on_cancel())

    dialog.wait_window()
    return pw

def insert_tree_items(parent, node):
    """Рекурсивное добавление элементов в дерево"""
    for key, val in node.items():
        if not key:  # пропускаем пустые ключи
            continue
        if isinstance(val, dict):
            item_id = tree.insert(parent, "end", text=key, open=False, tags=("folder",))
            insert_tree_items(item_id, val)
        else:
            tree.insert(parent, "end", text=key, open=False)

def reset_ui_state(keep_buttons=False):
    global current_path
    current_path = []
    text.config(state="disabled")
    text.delete("1.0", tk.END)
    save_button.config(state="disabled")
    
    if not keep_buttons:
        add_folder_button.config(state="normal")
        add_note_button.config(state="normal")
        delete_button.config(state="disabled")
        rename_button.config(state="disabled")
        move_button.config(state="disabled")  # Добавляем сброс состояния кнопки перемещения


def on_tree_select(event=None):
    global current_path, is_note_selected
    selected = tree.selection()
    if not selected:
        reset_ui_state()
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
        # Выбрана заметка
        is_note_selected = True
        text.config(state="normal")
        text.delete("1.0", tk.END)
        text.insert(tk.END, val)
        save_button.config(state="normal")
        add_folder_button.config(state="disabled")
        add_note_button.config(state="disabled")
        delete_button.config(state="normal")
        rename_button.config(state="normal")
        move_button.config(state="normal")  # Активируем кнопку перемещения
    else:
        # Выбрана папка
        is_note_selected = False
        text.config(state="disabled")
        text.delete("1.0", tk.END)
        save_button.config(state="disabled")
        add_folder_button.config(state="normal")
        add_note_button.config(state="normal")
        delete_button.config(state="normal")
        rename_button.config(state="normal")
        move_button.config(state="normal")  # Активируем кнопку перемещения и для папок

def block_edit_if_not_note(event):
    if not is_note_selected:
        return "break"  # блокирует нажатие клавиши


def on_tree_click(event):
    """Обработчик клика по дереву (для снятия выделения)"""
    item = tree.identify_row(event.y)
    if not item:
        tree.selection_remove(tree.selection())
        reset_ui_state()
        global current_path
        current_path = []
        text.config(state="disabled")
        text.delete("1.0", tk.END)
        save_button.config(state="disabled")
        add_folder_button.config(state="normal")
        add_note_button.config(state="normal")
        delete_button.config(state="disabled")
        rename_button.config(state="disabled")

def refresh_tree(current_data=None):
    """Обновление дерева с данными"""
    if current_data is None:
        current_data = data
    
    tree.delete(*tree.get_children())
    insert_tree_items("", current_data)
    
    # Сброс состояния интерфейса
    text.delete("1.0", tk.END)
    text.config(state="disabled")
    save_button.config(state="disabled")
    add_folder_button.config(state="normal")
    add_note_button.config(state="normal")
    delete_button.config(state="disabled")
    rename_button.config(state="disabled")
    
    global current_path
    current_path = []

# ==============================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С ЗАМЕТКАМИ И ПАПКАМИ
# ==============================================

def get_all_folders(node=None, current_path=None, folders_list=None):
    """Рекурсивно собирает все папки в структуре"""
    if folders_list is None:
        folders_list = []
    if current_path is None:
        current_path = []
    if node is None:
        node = data
    
    for key, value in node.items():
        if isinstance(value, dict):
            # Это папка - добавляем её путь
            folder_path = current_path + [key]
            folders_list.append(folder_path)
            # Рекурсивно обрабатываем вложенные папки
            get_all_folders(value, folder_path, folders_list)
    
    return folders_list

def get_all_folders(node=None, current_path=None, folders_list=None):
    """Рекурсивно собирает все папки в структуре"""
    if folders_list is None:
        folders_list = []
    if current_path is None:
        current_path = []
    if node is None:
        node = data
    
    for key, value in node.items():
        if isinstance(value, dict):
            # Это папка - добавляем её путь
            folder_path = current_path + [key]
            folders_list.append(folder_path)
            # Рекурсивно обрабатываем вложенные папки
            get_all_folders(value, folder_path, folders_list)
    
    return folders_list




def move_item():
    """Перемещение выбранного элемента в другую папку"""
    global current_path
    if not current_path:
        return
    
    # Сохраняем имя перемещаемого элемента
    item_name = current_path[-1]
    
    # Получаем список всех папок в виде путей
    all_folders = get_all_folders()
    
    # Исключаем текущую папку и её подпапки
    valid_folders = []
    for folder_path in all_folders:
        # Проверяем, не является ли эта папка родительской или текущей
        if not (current_path == folder_path or 
                (len(current_path) > len(folder_path) and current_path[:len(folder_path)] == folder_path)):
            valid_folders.append(folder_path)
    
    # Добавляем корневую папку (пустой список)
    valid_folders.insert(0, [])
    
    # Создаем диалог для выбора папки
    move_dialog = tk.Toplevel(root)
    move_dialog.title("Выберите папку для перемещения")
    move_dialog.transient(root)
    move_dialog.grab_set()
    
    # Устанавливаем размеры окна
    dialog_width = 400
    dialog_height = 500
    
    # Центрируем окно перемещения относительно главного окна
    center_window(move_dialog, dialog_width, dialog_height, parent=root)
    
    
    # Создаем Treeview для отображения структуры папок
    move_tree = ttk.Treeview(move_dialog, columns=("Name",), show="tree")
    move_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Заполняем Treeview
    def insert_folders(parent, path_prefix, folders):
        for folder_path in folders:
            # Проверяем, начинается ли путь папки с текущего префикса
            if len(folder_path) == len(path_prefix) + 1 and folder_path[:len(path_prefix)] == path_prefix:
                item_id = move_tree.insert(parent, "end", text=folder_path[-1], open=False, tags=("folder",))
                insert_folders(item_id, folder_path, folders)
    
    # Вставляем корневую папку
    root_item = move_tree.insert("", "end", text="Корневая папка", open=True)
    insert_folders(root_item, [], valid_folders)
    
    # Кнопки для диалога
    button_frame = tk.Frame(move_dialog)
    button_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def on_move():
        selected = move_tree.selection()
        if not selected:
            messagebox.showerror("Ошибка", "Выберите папку для перемещения")
            return
        
        selected_item = selected[0]
        # Получаем путь к выбранной папке
        target_path = []
        while selected_item:
            item_text = move_tree.item(selected_item, "text")
            if item_text != "Корневая папка":
                target_path.insert(0, item_text)
            selected_item = move_tree.parent(selected_item)
        
        # Находим исходный элемент
        source_node = data
        for p in current_path[:-1]:
            source_node = source_node.get(p, {})
        
        # Сохраняем значение элемента
        item_value = source_node[item_name]
        
        # Удаляем элемент из исходного местоположения
        del source_node[item_name]
        
        # Находим целевую папку
        target_node = data
        for p in target_path:
            target_node = target_node.setdefault(p, {})
        
        # Проверяем, нет ли уже элемента с таким именем
        if item_name in target_node:
            messagebox.showerror("Ошибка", "В целевой папке уже есть элемент с таким именем")
            # Возвращаем элемент на место
            source_node[item_name] = item_value
            return
        
        # Добавляем элемент в новую папку
        target_node[item_name] = item_value
        
        # Сохраняем изменения
        save_data()
        refresh_tree()
        move_dialog.destroy()
        messagebox.showinfo("Успех", f"Элемент '{item_name}' перемещён")
        reset_ui_state()  # Сбрасываем состояние интерфейса
    
    move_button = tk.Button(button_frame, text="Переместить", command=on_move)
    move_button.pack(side=tk.LEFT, padx=5)
    
    cancel_button = tk.Button(button_frame, text="Отмена", command=move_dialog.destroy)
    cancel_button.pack(side=tk.RIGHT, padx=5)


def save_note(silent=False):
    """Сохранение текущей заметки"""
    global current_path
    if not current_path:
        return
    
    node = data
    for p in current_path[:-1]:
        node = node.setdefault(p, {})
    
    node[current_path[-1]] = text.get("1.0", tk.END).rstrip("\n")
    save_data()
    if not silent:
        messagebox.showinfo("Сохранено", "Заметка сохранена!")

def add_folder():
    """Добавление новой папки"""
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
    """Добавление новой заметки"""
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
    """Удаление выбранного элемента"""
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
    """Переименование выбранного элемента"""
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

# ==============================================
# ФУНКЦИИ ДЛЯ ПОИСКА
# ==============================================

def on_search_change(*args):
    """Обработчик изменения текста в поле поиска"""
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
        collect_notes()
        for item_id in search_results:
            tree.item(item_id, tags=("found",))
        tree.tag_configure("found", foreground="green")
        
        if search_results:
            search_index = 0
            select_search_result()

def select_search_result():
    """Выбор текущего результата поиска"""
    if 0 <= search_index < len(search_results):
        item = search_results[search_index]
        tree.selection_set(item)
        tree.focus(item)
        tree.see(item)
        on_tree_select(None)

def move_search(direction):
    """Перемещение между результатами поиска"""
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

def on_text_change(event=None):
    if text.edit_modified():
        save_note(silent=True)
        text.edit_modified(False)

#Установка иконки в окне
def set_icon():
    try:
        root.iconbitmap(r'C:\Users\Nik\Downloads\ico.ico')
    except Exception as e:
        print(f"Ошибка при установке иконки: {e}")
        
# ==============================================
# ОСНОВНОЕ ОКНО ПРИЛОЖЕНИЯ
# ==============================================

# Создание главного окна
root = tk.Tk()
root.title("Заметки")
window_width = 950
window_height = 600
center_window(root, window_width, window_height)

root.after(0, set_icon)  # Загружаем иконку после запуска mainloop

# Настройка шрифтов
default_font = tkfont.Font(family="Arial", size=10)

# Настройка стилей для Treeview
style = ttk.Style()
style.configure("Treeview", font=default_font, rowheight=30)  # увеличенная высота строки
style.configure("Treeview.Heading", font=(default_font.actual("family"), 15))

# ==============================================
# ЭЛЕМЕНТЫ ИНТЕРФЕЙСА
# ==============================================

# Верхняя панель с кнопками
button_frame = tk.Frame(root)
button_frame.pack(side=tk.TOP, fill=tk.X)

# Кнопки в button_frame
save_button = tk.Button(button_frame, text="Сохранить заметку", command=save_note, state="disabled", font=("Arial", 9, "bold"))
save_button.pack(side=tk.LEFT, padx=5, pady=5)

add_folder_button = tk.Button(button_frame, text="Добавить папку", command=add_folder, font=("Arial", 9, "bold"))
add_folder_button.pack(side=tk.LEFT, padx=5, pady=5)

add_note_button = tk.Button(button_frame, text="Добавить заметку", command=add_note, font=("Arial", 9, "bold"))
add_note_button.pack(side=tk.LEFT, padx=5, pady=5)

delete_button = tk.Button(button_frame, text="Удалить", command=delete_item, state="disabled", font=("Arial", 9, "bold"))
delete_button.pack(side=tk.LEFT, padx=5, pady=5)

rename_button = tk.Button(button_frame, text="Переименовать", command=rename_item, state="disabled", font=("Arial", 9, "bold"))
rename_button.pack(side=tk.LEFT, padx=5, pady=5)

# Новая кнопка "Переместить"
move_button = tk.Button(button_frame, text="Переместить", command=lambda: move_item(), state="disabled", font=("Arial", 9, "bold"))
move_button.pack(side=tk.LEFT, padx=5, pady=5)

password_button = tk.Button(button_frame, text="🔑Пароль", command=lambda: manage_password(), font=("Arial", 9, "bold"))
password_button.pack(side=tk.RIGHT, padx=5, pady=5)

# Панель поиска
search_var = tk.StringVar()
search_results = []  # список item_id найденных элементов
search_index = -1    # текущий индекс выбранного элемента в поиске
search_var.trace_add("write", on_search_change)
search_frame = tk.Frame(root)
search_frame.pack(fill=tk.X, padx=5, pady=5)
search_label = tk.Label(search_frame, text="Поиск:", font=("Arial", 9, "bold"))
search_label.pack(side=tk.LEFT)
search_entry = tk.Entry(search_frame, textvariable=search_var, font=("Arial", 9, "bold"))
search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

# Кнопки "Назад" и "Вперёд" для поиска
prev_button = tk.Button(search_frame, text="<", command=lambda: move_search(-1), font=("Arial", 9, "bold"))
prev_button.pack(side=tk.LEFT, padx=5)

next_button = tk.Button(search_frame, text=">", command=lambda: move_search(1), font=("Arial", 9, "bold"))
next_button.pack(side=tk.LEFT)

# Основной фрейм под дерево и текст
frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)


tree_frame = tk.Frame(frame)
tree_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)


# Полоса прокрутки для дерева
tree_scroll = tk.Scrollbar(tree_frame,width=5)
tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)


# Дерево заметок
tree = ttk.Treeview(tree_frame, columns=("Name",), show="tree", 
                    yscrollcommand=tree_scroll.set)
tree.column("#0", width=50, minwidth=230, stretch=True)
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)





# Привязка прокрутки
tree_scroll.config(command=tree.yview)

# Фрейм для текстового поля
text_frame = tk.Frame(frame)
text_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Полоса прокрутки для текстового поля
scrollbar = tk.Scrollbar(text_frame,width=10)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Текстовое поле с привязкой скроллбара
text = tk.Text(text_frame, wrap=tk.WORD, width=50, font=default_font, yscrollcommand=scrollbar.set)
text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
text.bind("<<Modified>>", on_text_change)

# Настройка полосы прокрутки
scrollbar.config(command=text.yview)

#Оформление для папки
folder_font = tkfont.Font(family="Arial", size=11, weight="bold")
tree.tag_configure("folder", font=folder_font)

# ==============================================
# ЗАГРУЗКА ДАННЫХ И ЗАПУСК ПРИЛОЖЕНИЯ
# ==============================================

# Загрузка данных
data = load_data()
current_path = []
refresh_tree()

# Привязка обработчиков событий
tree.bind("<<TreeviewSelect>>", on_tree_select)
tree.bind("<Button-1>", on_tree_click)
text.bind("<Key>", block_edit_if_not_note)

# Запуск главного цикла
root.mainloop()
