import random
import math
import sys
import os
from pathlib import Path


class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.modulus = None

    @staticmethod
    def is_prime(n, k=10):
        """Тест Миллера-Рабина на простоту числа"""
        if n < 2:
            return False
        if n in [2, 3]:
            return True
        if n % 2 == 0:
            return False

        # Записываем n-1 как d * 2^r
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Проводим k раундов теста
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits=512):
        """Генерация простого числа заданной длины в битах"""
        while True:
            num = random.getrandbits(bits)
            # Устанавливаем старший и младший биты в 1
            num |= (1 << bits - 1) | 1
            if RSA.is_prime(num):
                return num

    @staticmethod
    def gcd(a, b):
        """Наибольший общий делитель"""
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a, b):
        """Расширенный алгоритм Евклида"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSA.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    @staticmethod
    def mod_inverse(e, phi):
        """Нахождение обратного элемента по модулю"""
        gcd, x, _ = RSA.extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Обратный элемент не существует")
        return x % phi

    def generate_keypair(self, bits=1024):
        """Генерация ключевой пары RSA"""
        print(f"Генерация ключей длиной {bits} бит...")

        # Генерируем два простых числа
        p = self.generate_prime(bits // 2)
        q = self.generate_prime(bits // 2)

        # Вычисляем модуль n = p * q
        n = p * q
        self.modulus = n

        # Вычисляем функцию Эйлера φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)

        # Выбираем открытую экспоненту e (обычно 65537)
        e = 65537
        while self.gcd(e, phi) != 1:
            e = random.randrange(2, phi)

        # Вычисляем закрытую экспоненту d
        d = self.mod_inverse(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)

        return self.public_key, self.private_key

    def save_keys(self, public_file="public_key.txt", private_file="private_key.txt"):
        """Сохранение ключей в файлы"""
        with open(public_file, 'w') as f:
            f.write(f"{self.public_key[0]}\n{self.public_key[1]}")
        with open(private_file, 'w') as f:
            f.write(f"{self.private_key[0]}\n{self.private_key[1]}")
        print(f"Ключи сохранены в файлы: {public_file}, {private_file}")

    def load_keys(self, public_file=None, private_file=None):
        """Загрузка ключей из файлов"""
        if public_file:
            with open(public_file, 'r') as f:
                e = int(f.readline().strip())
                n = int(f.readline().strip())
                self.public_key = (e, n)
                self.modulus = n

        if private_file:
            with open(private_file, 'r') as f:
                d = int(f.readline().strip())
                n = int(f.readline().strip())
                self.private_key = (d, n)
                self.modulus = n

    def encrypt_block(self, plaintext_block):
        """Шифрование одного блока текста"""
        if not self.public_key:
            raise ValueError("Открытый ключ не загружен")
        e, n = self.public_key
        return pow(plaintext_block, e, n)

    def decrypt_block(self, ciphertext_block):
        """Расшифрование одного блока текста"""
        if not self.private_key:
            raise ValueError("Закрытый ключ не загружен")
        d, n = self.private_key
        return pow(ciphertext_block, d, n)

    def text_to_blocks(self, text):
        """Преобразование текста в числовые блоки"""
        blocks = []
        block_size = (self.modulus.bit_length() - 1) // 8

        for i in range(0, len(text), block_size):
            block_text = text[i:i + block_size]
            block_num = 0
            for char in block_text:
                block_num = (block_num << 8) | ord(char)
            blocks.append(block_num)

        return blocks

    def blocks_to_text(self, blocks):
        """Преобразование числовых блоков обратно в текст"""
        text = ""
        for block in blocks:
            block_text = ""
            while block > 0:
                block_text = chr(block & 0xFF) + block_text
                block >>= 8
            text += block_text
        return text

    def encrypt_file(self, input_file, output_file):
        """Шифрование файла"""
        if not self.public_key:
            raise ValueError("Открытый ключ не загружен")

        # Читаем исходный текст
        with open(input_file, 'r', encoding='utf-8') as f:
            plaintext = f.read()

        print(f"Исходный текст ({len(plaintext)} символов)")

        # Преобразуем текст в блоки
        blocks = self.text_to_blocks(plaintext)
        print(f"Разбито на {len(blocks)} блоков")

        # Шифруем блоки
        encrypted_blocks = [self.encrypt_block(block) for block in blocks]

        # Сохраняем зашифрованные блоки
        with open(output_file, 'w') as f:
            for block in encrypted_blocks:
                f.write(f"{block}\n")

        print(f"Зашифрованный текст сохранен в {output_file}")
        return True

    def decrypt_file(self, input_file, output_file):
        """Расшифрование файла"""
        if not self.private_key:
            raise ValueError("Закрытый ключ не загружен")

        # Читаем зашифрованные блоки
        with open(input_file, 'r') as f:
            encrypted_blocks = [int(line.strip()) for line in f if line.strip()]

        print(f"Найдено {len(encrypted_blocks)} зашифрованных блоков")

        # Расшифровываем блоки
        decrypted_blocks = [self.decrypt_block(block) for block in encrypted_blocks]

        # Преобразуем обратно в текст
        plaintext = self.blocks_to_text(decrypted_blocks)

        # Сохраняем расшифрованный текст
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(plaintext)

        print(f"Расшифрованный текст сохранен в {output_file}")
        return True

    #Для криптоанализа
    @staticmethod
    def chinese_remainder_theorem(remainders, moduli):
        """
        Китайская теорема об остатках.
        Находит x такое, что x ≡ r_i (mod m_i) для всех i.

        Параметры:
            remainders: список остатков r_i
            moduli: список модулей m_i (попарно взаимно простых)

        Возвращает:
            x (mod произведение всех moduli)
        """
        if len(remainders) != len(moduli):
            raise ValueError("Количество остатков и модулей должно совпадать")

        total = 0
        prod = 1
        for m in moduli:
            prod *= m

        for r, m in zip(remainders, moduli):
            p = prod // m
            total += r * RSA.mod_inverse(p, m) * p

        return total % prod

    @staticmethod
    def integer_cuberoot(n):
        """
        Целочисленный кубический корень.
        Возвращает наибольшее целое x, такое что x^3 ≤ n.
        """
        if n < 0:
            return -RSA.integer_cuberoot(-n)
        if n == 0:
            return 0

        low, high = 1, 1
        while high ** 3 <= n:
            high *= 2

        while low <= high:
            mid = (low + high) // 2
            mid_cubed = mid ** 3
            if mid_cubed == n:
                return mid
            elif mid_cubed < n:
                low = mid + 1
            else:
                high = mid - 1

        return high

    def hastad_attack(self, ciphertexts, moduli, e=3):
        """
        Атака Хостеда для малой экспоненты e.
        """
        if len(moduli) != e:
            raise ValueError(f"Необходимо {e} модулей")

        # Определяем количество блоков
        if isinstance(ciphertexts[0], list):
            num_blocks = len(ciphertexts[0])
            # Транспонируем для удобства: получаем список блоков
            block_ciphertexts = []
            for i in range(num_blocks):
                block_ciphertexts.append([ciphertexts[j][i] for j in range(e)])
        else:
            # ciphertexts - плоский список для одного блока
            if len(ciphertexts) != e:
                raise ValueError(f"Необходимо {e} шифротекстов и {e} модулей")
            block_ciphertexts = [ciphertexts]

        recovered_blocks = []

        print(f"Применяем атаку Хостеда к {len(block_ciphertexts)} блокам")

        for block_idx, block_ciphers in enumerate(block_ciphertexts):
            print(f"\nБлок {block_idx + 1}/{len(block_ciphertexts)}:")
            print(f"  Применяем китайскую теорему об остатках к {e} шифротекстам")
            x = self.chinese_remainder_theorem(block_ciphers, moduli)
            print(f"  Найдено x = {x}")

            print(f"  Извлекаем корень {e}-й степени")
            m_block = self.integer_cuberoot(x)

            if pow(m_block, e) == x:
                print(f"  Блок восстановлен: {m_block}")
                recovered_blocks.append(m_block)
            else:
                print(f"  Не удалось извлечь точный корень для блока {block_idx + 1}")
                return None

        print(f"\nАтака успешна! Восстановлено сообщение: {recovered_blocks}")
        return recovered_blocks

    def demonstrate_hastad_attack(self):
        """Демонстрация атаки Хостеда с численным примером."""
        print("ДЕМОНСТРАЦИЯ АТАКИ ХОСТЕДА")

        e = 3
        m = [112, 121, 116, 104, 111, 110]

        print(f"\nИсходное сообщение (блоки): m = {m}")
        print(f"Текст: {self.blocks_to_text(m)}")

        n1, n2, n3 = 187, 247, 667
        print(f"\nМодули получателей:")
        print(f"  n1 = {n1}")
        print(f"  n2 = {n2}")
        print(f"  n3 = {n3}")

        # Вычисляем шифротексты для каждого блока
        ciphertexts_per_modulus = [[], [], []]

        print(f"\nПерехваченные шифротексты:")
        for block_idx, block in enumerate(m):
            c1 = pow(block, e, n1)
            c2 = pow(block, e, n2)
            c3 = pow(block, e, n3)

            ciphertexts_per_modulus[0].append(c1)
            ciphertexts_per_modulus[1].append(c2)
            ciphertexts_per_modulus[2].append(c3)

            print(f"  Блок {block_idx + 1} (m={block}):")
            print(f"    c1 = {block}^{e} mod {n1} = {c1}")
            print(f"    c2 = {block}^{e} mod {n2} = {c2}")
            print(f"    c3 = {block}^{e} mod {n3} = {c3}")

        print(f"\nПРОВЕДЕНИЕ АТАКИ")
        m_recovered = self.hastad_attack(ciphertexts_per_modulus, [n1, n2, n3], e)

        # Проверка
        print(f"\nРЕЗУЛЬТАТ")
        if m_recovered is not None:
            print(f"Восстановленные блоки: {m_recovered}")
            print(f"Восстановленный текст: {self.blocks_to_text(m_recovered)}")

            if m_recovered == m:
                print(f"АТАКА УСПЕШНА! Сообщение полностью восстановлено!")
            else:
                print(f"Частичное несовпадение. Получено: {m_recovered}, ожидалось: {m}")
        else:
            print("Атака не удалась.")

        # Дополнительная проверка условия успешности
        print(f"\nУСЛОВИЕ УСПЕШНОСТИ")
        n_product = n1 * n2 * n3
        print(f"n1·n2·n3 = {n_product}")

        for block_idx, block in enumerate(m):
            m_cubed = block ** e
            print(f"Блок {block_idx + 1}: m^{e} = {m_cubed}")
            if m_cubed < n_product:
                print(f"  {m_cubed} < {n_product} - условие выполнено, атака возможна")
            else:
                print(f"  {m_cubed} ≥ {n_product} - условие не выполнено, атака невозможна")

        return m_recovered


def print_menu():
    print("КРИПТОСИСТЕМА RSA")
    print("1. Сгенерировать ключевую пару")
    print("2. Загрузить ключи из файлов")
    print("3. Зашифровать файл")
    print("4. Расшифровать файл")
    print("5. Показать информацию о ключах")
    print("6. Выход")
    print("*7. Демонстрация атаки Хостеда")


def get_file_path(prompt):
    """Получение пути к файлу с проверкой существования"""
    while True:
        filepath = input(prompt).strip()
        if not filepath:
            print("Путь не может быть пустым!")
            continue
        return filepath


def main():
    rsa = RSA()

    while True:
        print_menu()
        choice = input("Выберите действие (1-7): ").strip()

        if choice == '1':
            # Генерация ключей
            try:
                bits = 1024

                public_key, private_key = rsa.generate_keypair(bits)
                print(f"\nОткрытый ключ (e, n):")
                print(f"e = {public_key[0]}")
                print(f"n = {public_key[1]}")
                print(f"\nЗакрытый ключ (d, n):")
                print(f"d = {private_key[0]}")
                print(f"n = {private_key[1]}")

                save = input("\nСохранить ключи в файлы? (y/n): ").strip().lower()
                if save == 'y':
                    pub_file = input("Имя файла для открытого ключа [public_key.txt]: ").strip()
                    priv_file = input("Имя файла для закрытого ключа [private_key.txt]: ").strip()
                    rsa.save_keys(pub_file or "public_key.txt", priv_file or "private_key.txt")

            except Exception as e:
                print(f"Ошибка при генерации ключей: {e}")

        elif choice == '2':
            # Загрузка ключей
            pub_file = get_file_path("Введите путь к файлу с открытым ключом: ")
            priv_file = get_file_path("Введите путь к файлу с закрытым ключом: ")

            try:
                rsa.load_keys(pub_file, priv_file)
                if rsa.public_key:
                    print("Открытый ключ успешно загружен")
                if rsa.private_key:
                    print("Закрытый ключ успешно загружен")
            except Exception as e:
                print(f"Ошибка при загрузке ключей: {e}")

        elif choice == '3':
            # Шифрование файла
            if not rsa.public_key:
                print("Ошибка: Открытый ключ не загружен!")
                print("Сначала сгенерируйте или загрузите ключи.")
                continue

            input_file = get_file_path("Введите путь к файлу с открытым текстом: ")
            if not os.path.exists(input_file):
                print("Файл не найден!")
                continue

            output_file = get_file_path("Введите путь для сохранения шифротекста: ")

            try:
                rsa.encrypt_file(input_file, output_file)
                print("Шифрование успешно завершено!")
            except Exception as e:
                print(f"Ошибка при шифровании: {e}")

        elif choice == '4':
            # Расшифрование файла
            if not rsa.private_key:
                print("Ошибка: Закрытый ключ не загружен!")
                print("Сначала сгенерируйте или загрузите ключи.")
                continue

            input_file = get_file_path("Введите путь к файлу с шифротекстом: ")
            if not os.path.exists(input_file):
                print("Файл не найден!")
                continue

            output_file = get_file_path("Введите путь для сохранения расшифрованного текста: ")

            try:
                rsa.decrypt_file(input_file, output_file)
                print("Расшифрование успешно завершено!")
            except Exception as e:
                print(f"Ошибка при расшифровании: {e}")

        elif choice == '5':
            # Информация о ключах
            print("ИНФОРМАЦИЯ О КЛЮЧАХ")
            if rsa.public_key:
                e, n = rsa.public_key
                print(f"Открытый ключ (e, n):")
                print(f"  Экспонента e: {e}")
                print(f"  Модуль n: {n} (длина: {n.bit_length()} бит)")
            else:
                print("Открытый ключ не загружен")

            print()
            if rsa.private_key:
                d, n = rsa.private_key
                print(f"Закрытый ключ (d, n):")
                print(f"  Экспонента d: {d}")
                print(f"  Модуль n: {n} (длина: {n.bit_length()} бит)")
            else:
                print("Закрытый ключ не загружен")

        elif choice == '6':
            print("До свидания!")
            sys.exit(0)

        elif choice == '7':
            rsa.demonstrate_hastad_attack()

        else:
            print("Неверный выбор! Пожалуйста, выберите 1-6.")


if __name__ == "__main__":
    main()