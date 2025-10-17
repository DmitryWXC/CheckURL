import re
from urllib.parse import urlparse
import socket
import idna
import requests
from datetime import datetime
from bs4 import BeautifulSoup
try:
    import whois
except ImportError:
    whois = None

def is_ip_address(host):
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        return False

def is_punycode(host):
    try:
        idna.decode(host)
        return False
    except Exception:
        return True

def has_suspicious_port(parsed):
    # Разрешён только стандартный порт 443 для https
    if parsed.port and parsed.port != 443:
        return True
    return False

def has_suspicious_path(parsed):
    # Проверка на подозрительные символы в пути
    suspicious_path_patterns = [r'\..', r'%', r'\\', r'\$', r'\*', r'\|', r'\<', r'\>', r'\"', r"'", r'\`']
    for pattern in suspicious_path_patterns:
        if re.search(pattern, parsed.path):
            return True
    return False

def has_many_subdomains(host):
    # Больше 3 поддоменов — подозрительно
    return host.count('.') > 3

def domain_exists(host):
    try:
        socket.gethostbyname(host)
        return True
    except socket.error:
        return False

def get_html_code(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; SafeURLChecker/1.0)'
        }
        resp = requests.get(url, headers=headers, timeout=5, allow_redirects=True, stream=True)
        # Ограничим размер ответа, чтобы не грузить большие страницы
        content = b''
        max_size = 1024 * 1024  # 1 MB
        for chunk in resp.iter_content(10240):
            content += chunk
            if len(content) > max_size:
                break
        # Декодируем только текст, не выполняем скрипты
        html = content.decode(resp.encoding or 'utf-8', errors='replace')
        return True, html, resp.status_code, resp.url, len(resp.history)
    except Exception as e:
        return False, f"Ошибка при получении HTML: {e}", None, None, None

def analyze_html(html):
    report = []
    # Проверка на наличие <iframe>
    if re.search(r'<iframe', html, re.IGNORECASE):
        report.append("Обнаружен тег <iframe> (часто используется для фишинга)")
    # Проверка на наличие <script>
    if re.search(r'<script', html, re.IGNORECASE):
        report.append("Обнаружен тег <script> (может быть использован для вредоносного кода)")
    # Проверка на подозрительные формы
    if re.search(r'<form[^>]*action=["\']?http', html, re.IGNORECASE):
        report.append("Форма отправляет данные на внешний адрес (подозрительно)")
    # Проверка на email-адреса
    if re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html):
        report.append("В HTML обнаружены email-адреса (часто на фишинговых сайтах)")
    # Проверка на телефоны
    if re.search(r'\+?\d{1,3}[\s-]?\(?\d{1,5}\)?[\s-]?\d{1,5}[\s-]?\d{1,5}', html):
        report.append("В HTML обнаружены телефонные номера")
    return report

def is_similar_to_popular_domains(host):
    # Совпадение с популярным доменом — не подозрительно
    popular = ["google.com", "yandex.ru", "mail.ru", "vk.com", "facebook.com", "github.com"]
    for pop in popular:
        if host == pop:
            return False, pop  # Совпадение — не подозрительно
        # Проверка на похожесть (например, g00gle.com)
        host_simple = host.replace('0', 'o').replace('1', 'l')
        if host_simple != pop and (host_simple in pop or pop in host_simple):
            return True, pop
    return False, None

def find_suspicious_words(text):
    # Расширенный список подозрительных слов
    words = [
        'virus', 'hack', 'exploit', 'trojan', 'worm', 'ransomware', 'crack', 'free', 'porn', 'adult', 'casino',
        'bitcoin', 'crypto', 'payday', 'loan', 'phish', 'malware', 'spyware', 'carding', 'card', 'cvv', 'paypal',
        'bank', 'login', 'secure', 'update', 'verify', 'account', 'password', 'win', 'prize', 'gift', 'xxx', 'sex',
        'download', 'keygen', 'serial', 'generator', 'cheat', 'bet', 'gamble', 'pharma', 'pill', 'shop', 'sale',
        'deal', 'offer', 'bonus', 'money', 'earn', 'investment', 'invest', 'forex', 'binary', 'escort', 'dating',
        'loan', 'credit', 'finance', 'insurance', 'support', 'help', 'unlock', 'unblock', 'bypass', 'anonymous',
        'proxy', 'vpn', 'tor', 'darknet', 'deepweb', 'blackjack', 'roulette', 'poker', 'casino', 'lottery', 'sweepstake'
    ]
    found = []
    for w in words:
        if w in text.lower():
            found.append(w)
    return found

def get_whois_info(domain):
    if whois is None:
        return {'error': "Модуль python-whois не установлен. Установите его командой: pip install python-whois"}
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = None
        if creation:
            age_days = (datetime.now() - creation).days
        country = w.country if hasattr(w, 'country') else None
        registrar = w.registrar if hasattr(w, 'registrar') else None
        return {
            'creation_date': creation,
            'age_days': age_days,
            'country': country,
            'registrar': registrar
        }
    except Exception as e:
        return {'error': str(e)}

def generate_osint_links(domain):
    return {
        'urlvoid': f'https://www.urlvoid.com/scan/{domain}/',
        'scamdoc': f'https://www.scamdoc.com/view/website/{domain}',
        'virustotal': f'https://www.virustotal.com/gui/domain/{domain}/detection',
        'abuseipdb': f'https://www.abuseipdb.com/check/{domain}',
        'talos': f'https://talosintelligence.com/reputation_center/lookup?search={domain}',
        'umbrella': f'https://investigate.umbrella.com/domain-view/name/{domain}/view',
        'hybrid_analysis': f'https://www.hybrid-analysis.com/search?query={domain}',
        'alienvault_otx': f'https://otx.alienvault.com/indicator/domain/{domain}',
        'sucuri': f'https://sitecheck.sucuri.net/results/{domain}',
        'google_transparency': f'https://transparencyreport.google.com/safe-browsing/search?url={domain}',
        'phishtank': f'https://www.phishtank.com/search.php?search={domain}',
        'ssllabs': f'https://www.ssllabs.com/ssltest/analyze.html?d={domain}',
        'abusech_urlhaus': f'https://urlhaus.abuse.ch/browse.php?search={domain}',
        'opentip_kaspersky': f'https://opentip.kaspersky.com/{domain}',
        'threatminer': f'https://www.threatminer.org/domain.php?q={domain}',
        'dnslytics': f'https://dnslytics.com/domain/{domain}',
        'domaintools': f'https://whois.domaintools.com/{domain}',
        'shodan': f'https://www.shodan.io/search?query={domain}',
        'censys': f'https://search.censys.io/domain/{domain}',
        'spyonweb': f'https://spyonweb.com/{domain}',
    }

def is_safe_url(url):
    checks = []
    regex = re.compile(
        r'^(?:http|https)://'  # http:// или https://
        r'(?:\S+)$', re.IGNORECASE)
    if re.match(regex, url) is None:
        checks.append((False, "Некорректный формат URL"))
        return False, checks, None, None, None, None

    parsed = urlparse(url)

    # Проверка на HTTPS
    if parsed.scheme != "https":
        checks.append((False, "Используется незащищённый протокол (не HTTPS)"))
    else:
        checks.append((True, "Используется HTTPS"))

    # Проверка на IP-адрес вместо домена
    if is_ip_address(parsed.hostname):
        checks.append((False, "Используется IP-адрес вместо доменного имени"))
    else:
        checks.append((True, "Используется доменное имя"))

    # Проверка на Punycode (подозрение на спуфинг)
    if is_punycode(parsed.hostname):
        checks.append((False, "Домен использует Punycode (возможен спуфинг)"))
    else:
        checks.append((True, "Домен не использует Punycode"))

    # Проверка на подозрительный порт
    if has_suspicious_port(parsed):
        checks.append((False, f"Подозрительный порт: {parsed.port}"))
    else:
        checks.append((True, "Порт стандартный или не указан"))

    # Проверка на подозрительный путь
    if has_suspicious_path(parsed):
        checks.append((False, "Подозрительные символы или конструкции в пути URL"))
    else:
        checks.append((True, "Путь URL не содержит подозрительных символов"))

    # Проверка на большое количество поддоменов
    if has_many_subdomains(parsed.hostname):
        checks.append((False, "Слишком много поддоменов в адресе"))
    else:
        checks.append((True, "Количество поддоменов в норме"))

    # Список подозрительных доменов (можно расширить)
    bad_domains = [
        "phishing.com", "malware.com", "badsite.ru"
    ]
    if any(bad in parsed.netloc for bad in bad_domains):
        checks.append((False, "Подозрительный домен из чёрного списка"))
    else:
        checks.append((True, "Домен не в чёрном списке"))

    # Проверка на подозрительные символы (например, Unicode spoofing)
    suspicious_unicode = [
        '\u202e', # Right-to-left override
        '\u200f', # Right-to-left mark
        '\u200e', # Left-to-right mark
    ]
    if any(char in url for char in suspicious_unicode):
        checks.append((False, "Обнаружены подозрительные символы Unicode в ссылке"))
    else:
        checks.append((True, "Подозрительных Unicode-символов не найдено"))

    # Проверка на вредоносные параметры
    bad_params = ["script", "alert", "onerror", "onload"]
    if any(param in parsed.query.lower() for param in bad_params):
        checks.append((False, "Вредоносные параметры в ссылке"))
    else:
        checks.append((True, "Вредоносных параметров не найдено"))

    # Проверка на фишинговые слова в домене
    phishing_keywords = ["login", "secure", "update", "verify", "account", "banking"]
    if any(word in parsed.netloc.lower() for word in phishing_keywords):
        checks.append((False, "В домене присутствуют подозрительные слова, возможен фишинг"))
    else:
        checks.append((True, "Подозрительных слов в домене не найдено"))

    # Проверка на слишком длинный домен или URL
    if len(url) > 2083:
        checks.append((False, "Слишком длинная ссылка (возможна попытка обхода фильтров)"))
    else:
        checks.append((True, "Длина ссылки в пределах нормы"))
    if len(parsed.netloc) > 253:
        checks.append((False, "Слишком длинное доменное имя"))
    else:
        checks.append((True, "Длина доменного имени в пределах нормы"))

    # Проверка на повторяющиеся символы (например, много точек или дефисов)
    if parsed.netloc.count('.') > 5 or parsed.netloc.count('-') > 10:
        checks.append((False, "Подозрительно много точек или дефисов в домене"))
    else:
        checks.append((True, "Количество точек и дефисов в домене в пределах нормы"))

    similar, pop = is_similar_to_popular_domains(parsed.hostname)
    if similar:
        checks.append((False, f"Домен похож на популярный ({pop}), возможен фишинг"))
    else:
        checks.append((True, "Домен не похож на популярные, фишинг маловероятен"))

    # Проверка существования домена
    if domain_exists(parsed.hostname):
        checks.append((True, "Домен существует (DNS lookup успешен)"))
        domain_ok = True
    else:
        checks.append((False, "Домен не существует (DNS lookup неудачен)"))
        domain_ok = False

    # Whois-информация
    whois_info = get_whois_info(parsed.hostname) if domain_ok else None

    # OSINT-ссылки
    osint_links = generate_osint_links(parsed.hostname)

    # Проверка на подозрительные слова в домене, пути и параметрах
    suspicious_words = set(find_suspicious_words(parsed.hostname or ''))
    suspicious_words.update(find_suspicious_words(parsed.path or ''))
    suspicious_words.update(find_suspicious_words(parsed.query or ''))
    if suspicious_words:
        checks.append((False, f"Обнаружены подозрительные слова: {', '.join(sorted(suspicious_words))}"))
    else:
        checks.append((True, "Подозрительных слов не найдено"))

    # Итоговая оценка
    # Если единственная "подозрительная" проверка — совпадение с популярным доменом, считаем ссылку безопасной
    only_popular_match = (
        len([x for x in checks if not x[0]]) == 1 and
        any('Домен похож на популярный' in x[1] for x in checks if not x[0])
    )
    is_safe = all(x[0] for x in checks) or only_popular_match
    return is_safe, checks, domain_ok, whois_info, osint_links, parsed.hostname

def check_urlvoid(domain):
    try:
        url = f'https://www.urlvoid.com/scan/{domain}/'
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(resp.text, 'html.parser')
        verdict = soup.find('span', class_='label label-success')
        if verdict and 'Clean' in verdict.text:
            return 'Clean'
        if 'blacklist' in resp.text.lower() or 'malicious' in resp.text.lower():
            return 'Blacklisted/Malicious'
        return 'Не удалось однозначно определить (проверьте вручную)'
    except Exception as e:
        return f'Ошибка: {e}'

def check_sucuri(domain):
    try:
        url = f'https://sitecheck.sucuri.net/results/{domain}'
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(resp.text, 'html.parser')
        verdict = soup.find('div', class_='sitecheck-status')
        if verdict:
            text = verdict.text.lower()
            if 'no malware' in text or 'site is clean' in text:
                return 'Clean'
            if 'malware' in text or 'blacklisted' in text or 'warning' in text:
                return 'Malicious/Blacklisted'
        return 'Не удалось однозначно определить (проверьте вручную)'
    except Exception as e:
        return f'Ошибка: {e}'

def check_abuseipdb(domain):
    try:
        url = f'https://www.abuseipdb.com/check/{domain}'
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        if 'has not been reported' in resp.text or 'No reports' in resp.text:
            return 'No reports (Clean)'
        if 'reported' in resp.text or 'abuse' in resp.text:
            return 'Reported/Abuse detected'
        return 'Не удалось однозначно определить (проверьте вручную)'
    except Exception as e:
        return f'Ошибка: {e}'

def check_scamdoc(domain):
    try:
        url = f'https://www.scamdoc.com/view/website/{domain}'
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(resp.text, 'html.parser')
        trust = soup.find('span', class_='score')
        if trust:
            score = trust.text.strip()
            return f'Trust score: {score}'
        if 'no result' in resp.text.lower():
            return 'Нет данных'
        return 'Не удалось однозначно определить (проверьте вручную)'
    except Exception as e:
        return f'Ошибка: {e}'

def check_phishtank(domain):
    try:
        url = f'https://www.phishtank.com/search.php?search={domain}'
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        if 'No results found' in resp.text:
            return 'No results (Clean)'
        if 'phish_id' in resp.text or 'phishing' in resp.text:
            return 'Phishing detected!'
        return 'Не удалось однозначно определить (проверьте вручную)'
    except Exception as e:
        return f'Ошибка: {e}'

def auto_osint_checks(domain):
    results = {}
    results['urlvoid'] = check_urlvoid(domain)
    results['sucuri'] = check_sucuri(domain)
    results['abuseipdb'] = check_abuseipdb(domain)
    results['scamdoc'] = check_scamdoc(domain)
    results['phishtank'] = check_phishtank(domain)
    return results

def main():
    while True:
        print("Введите ссылку для проверки, или -exit чтобы выйти")
        url = input(">>> ")
        if url.lower() == '-exit':
            break # Выходим
        safe, checks, domain_ok, whois_info, osint_links, domain = is_safe_url(url)
        print("\nПроверки:")
        for ok, msg in checks:
            print(f"{'[+]' if ok else '[-]'} {msg}")
        if not domain_ok:
            print("\nИтог: Домен не существует, дальнейшие проверки невозможны!")
        else:
            # Whois-информация
            print("\nWhois-информация:")
            if whois_info is None:
                print("Не удалось получить whois-информацию.")
            elif 'error' in whois_info:
                print(f"Ошибка: {whois_info['error']}")
            else:
                if whois_info.get('creation_date'):
                    print(f"- Дата регистрации: {whois_info['creation_date']}")
                if whois_info.get('age_days') is not None:
                    print(f"- Возраст домена: {whois_info['age_days']} дней")
                    if whois_info['age_days'] < 180:
                        print("  (Молодой домен — повышенный риск)")
                if whois_info.get('country'):
                    print(f"- Страна: {whois_info['country']}")
                if whois_info.get('registrar'):
                    print(f"- Регистратор: {whois_info['registrar']}")
            # OSINT-ссылки
            print("\nOSINT-ссылки:")
            for name, link in osint_links.items():
                print(f"- {name}: {link}")
            if not safe:
                print("\nИтог: Ссылка подозрительна или небезопасна!")
            else:
                print("\nИтог: Ссылка прошла все проверки!")
                # Проверка существования и получение HTML
                parsed = urlparse(url)
                if domain_exists(parsed.hostname):
                    fetch, html, status, final_url, redirects = get_html_code(url)
                    if fetch:
                        print(f"\nHTTP-статус: {status}")
                        print(f"Финальный URL после редиректов: {final_url}")
                        print(f"Количество редиректов: {redirects}")
                        html_report = analyze_html(html)
                        if html_report:
                            print("\nАнализ HTML:")
                            for item in html_report:
                                print(f"[-] {item}")
                        else:
                            print("\nHTML-код страницы не содержит явных подозрительных элементов.")
                        print("\nHTML-код страницы (первые 500 символов):\n", html[:500])
                    else:
                        print(f"\nОшибка при получении HTML: {html}")
                else:
                    print("\nДомен не существует, HTML получить невозможно.")
                print("\nАвтоматическая проверка по OSINT-сайтам:")
                auto_osint = auto_osint_checks(domain)
                for name, result in auto_osint.items():
                    print(f"- {name}: {result}")

if __name__ == "__main__":
    main()
