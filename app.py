import requests
import os
import argparse
import json
import time
import csv


class APIRequestExpection(Exception):
    pass


API_KEY = os.environ.get("URLSCAN_API_KEY", None)
if API_KEY is None:
    raise APIRequestExpection('URLSCAN_API_KEY is none, please make sure you export this variable.')


def bulkscan(file):
    to_csv = {}
    csv_file = "my_results.csv"

    with open(file) as urls_check:
        urls = urls_check.read().splitlines()
        if args.skip:
            urls = urls[1:]
    print("""Depending on number of URLs this may take a while, URLscan requires 2 second delay between
    URL requests!""")

    for url in urls:
        url = url.replace("\"", '')
        if args.public:
            public = "on"
        else:
            public = "off"

        request_data = {
            "url": url,
            "public": public
        }

        request_headers = {
            "API-Key": API_KEY,
            "Content-Type": "application/json"
        }

        r = requests.post(
            url="https://urlscan.io/api/v1/scan",
            headers=request_headers,
            data=json.dumps(request_data)
        )

        time.sleep(2)
        results = r.json()
        to_csv[results['url']] = results[str('result')]

    with open(csv_file, 'w') as csvfile:
        for x in to_csv.keys():
            csvfile.write("%s,%s\n" % (x, to_csv[x]))


def urlscan(url):
    if args.public:
        public = "on"
    else:
        public = "off"
    print(url)
    request_headers = {
        "API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    request_data = {
        "url": args.url,
        "public": public
    }
    r = requests.post(
        url="https://urlscan.io/api/v1/scan/",
        headers=request_headers,
        data=json.dumps(request_data)
    )
    print(r.json())


def parse_args():
    description = ""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-u", "--url", action="store", help="url to scan", metavar="url")
    parser.add_argument("-p", "--public", action="store_true", help="Omit this attribute to submit as private scan")
    parser.add_argument("-f", "--file", action= "store", help="File to scan")
    parser.add_argument("-s", "--skip", action="store_true", help="Add this for files with headers")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    if args.url:
        urlscan(args.url)


    if args.file:
        bulkscan(args.file)
