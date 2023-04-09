import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def crawler(url2, visited=None):
    if visited is None:
        visited = []

    if url2 not in visited:
        visited.append(url2)

        addresses = []
        site = requests.get(url2).text
        soup = BeautifulSoup(site, 'lxml')
        soup = soup.body

        try:
            links = soup.find_all('a')
            check = soup.find_all('a')
            for link in links:
                if 'href' in link.attrs:
                    if '#' in link['href'] or url2 == link['href']:
                        pass
                    elif link['href'].startswith(url2):
                        addresses.append(link['href'])
                    elif len(link['href']) < 12 :
                        full_url = urljoin(url2, link['href'])
                        addresses.append(full_url)
                    else:
                        pass

            for addr in addresses:
                if addr not in visited and addr.startswith('https://'):
                    try:
                        sub = requests.get(addr)
                        sub_html = sub.text
                        sub_status = sub.status_code
                        sub_soup = BeautifulSoup(sub_html, 'lxml')
                        if sub_status == 200:
                            print("For Sub address - ", addr)
                            print("characters: ", len(sub_html))
                            try:
                                forms = sub_soup.find_all('form', method="post")
                                print("num of forms: ", len(forms))
                            except:
                                print("No forms were found")
                            try:
                                sub_links = sub_soup.find_all('a')
                                print("num of links: ", len(sub_links))
                            except:
                                print("No links were found")
                            print()
                            crawler(addr, visited)
                    except requests.exceptions.TooManyRedirects:
                        print(f"Too many redirects for {addr}. Skipping.")
                        print()
        except:
            print("No links were found under address: ", url2)
            print()


def main_site(url):
    try:
        main = requests.get(url)
        main_html = main.text
        main_status = main.status_code
        main_soup = BeautifulSoup(main_html, 'lxml')
        if main_status == 200:
            print("For Address: ", url)
            print("characters: ", len(main_html))
            try:
                forms = main_soup.find_all('form', method="post")
                print("num of forms: ", len(forms))
            except:
                print("No forms were found")
            try:
                sub_links = main_soup.find_all('a')
                print("num of links: ", len(sub_links))
                print()
            except:
                print("No links were found")
                print()
            crawler(url)
    except:
        print("error")


main_site("https:// INSERT A URL .com/")
