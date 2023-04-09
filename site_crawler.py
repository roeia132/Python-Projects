import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Define the main crawling function
def crawler(url2, visited=None):
    # Initialize visited list if not provided
    if visited is None:
        visited = []

    # If the URL is not visited, add it to the visited list
    if url2 not in visited:
        visited.append(url2)

        # Initialize a list to store addresses
        addresses = []

        # Request the page content and parse it using BeautifulSoup
        site = requests.get(url2).text
        soup = BeautifulSoup(site, 'lxml')
        soup = soup.body

        try:
            # Find all anchor tags containing links
            links = soup.find_all('a')

            # Iterate through the links and process them accordingly
            for link in links:
                if 'href' in link.attrs:
                    # Ignore links containing '#' or self-referential links
                    if '#' in link['href'] or url2 == link['href']:
                        pass
                    # If the link starts with the base URL, add it to the list
                    elif link['href'].startswith(url2):
                        addresses.append(link['href'])
                    # If the link is short, join it with the base URL and add it to the list
                    elif len(link['href']) < 12:
                        full_url = urljoin(url2, link['href'])
                        addresses.append(full_url)
                    else:
                        pass

            # Iterate through the found addresses and process each one
            for addr in addresses:
                if addr not in visited and addr.startswith('https://'):
                    try:
                        # Request the subpage and parse it with BeautifulSoup
                        sub = requests.get(addr)
                        sub_html = sub.text
                        sub_status = sub.status_code
                        sub_soup = BeautifulSoup(sub_html, 'lxml')

                        # If the subpage is accessible, print its information
                        if sub_status == 200:
                            print("For Sub address - ", addr)
                            print("characters: ", len(sub_html))
                            try:
                                # Find all forms with a post method and print their count
                                forms = sub_soup.find_all('form', method="post")
                                print("num of forms: ", len(forms))
                            except:
                                print("No forms were found")
                            try:
                                # Find all links and print their count
                                sub_links = sub_soup.find_all('a')
                                print("num of links: ", len(sub_links))
                            except:
                                print("No links were found")
                            print()

                            # Recursively call the crawler function for the subpage
                            crawler(addr, visited)
                    except requests.exceptions.TooManyRedirects:
                        # If there are too many redirects, skip this address
                        print(f"Too many redirects for {addr}. Skipping.")
                        print()
        except:
            # If no links were found, print the information
            print("No links were found under address: ", url2)
            print()

# Main function for the main site
def main_site(url):
    try:
        # Request the main page content and parse it using BeautifulSoup
        main = requests.get(url)
        main_html = main.text
        main_status = main.status_code
        main_soup = BeautifulSoup(main_html, 'lxml')

        # If the main page is accessible, print its information
        if main_status == 200:
            print("For Address: ", url)
            print("characters: ", len(main_html))
            try:
                # Find all forms with a post method and print their count
                forms = main_soup.find_all('form', method="post")
                print("num of forms: ", len(forms))
            except:
                print("No forms were found")
            try:
                # Find all links and print their count
                sub_links = main_soup.find_all('a')
                print("num of links: ", len(sub_links))
                print()
            except:
                print("No links were found")
                print()

            # Call the crawler function for the main site
            crawler(url)
    except:
        # If there is an error, print it
        print("error")

# Call the main_site function with the target URL
main_site("https://attackit.co.il/")
