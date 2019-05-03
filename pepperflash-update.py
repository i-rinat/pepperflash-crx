# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT-0

from clint.textui import progress
from lxml import etree
import argparse
import hashlib
import os
import requests
import sys


def Config(app_id, platform, arch, channel, request_os, request_arch):
    class ConfigHolder:
        pass
    config = ConfigHolder()
    config.app_id = app_id
    config.platform = platform
    config.arch = arch
    config.channel = channel
    config.request_os = request_os
    config.request_arch = request_arch
    return config


def get_update_links(session, config):
    headers = {
        "X-Goog-Update-AppId": config.app_id,
        "X-Goog-Update-Interactivity": "fg",
        "X-Goog-Update-Updater": "chrome-74.0.3729.131",
        "Content-Type": "application/xml",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
                      "(KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36"
    }

    payload = (
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<request protocol="3.1" acceptformat="crx2,crx3" updater="chrome" ' +
        '         updaterversion="74.0.3729.131" prodversion="74.0.3729.131"' +
        '         prodchannel="{channel}" prod="chrome" ' +
        '         lang="en" os="{request_os}" arch="{request_arch}" ' +
        '         nacl_arch="x86-64">' +
        '   <os platform="{platform}" arch="{arch}" version=""/>' +
        '   <app appid="{app_id}" version="0.0.0.0" ' +
        '        installsource="ondemand" enabled="1">' +
        '       <updatecheck/>' +
        '   </app>' +
        '</request>').format(app_id=config.app_id, channel=config.channel,
                             platform=config.platform, arch=config.arch,
                             request_os=config.request_os,
                             request_arch=config.request_arch)
    r = session.post("https://update.googleapis.com/service/update2",
                     headers=headers, data=payload)
    if r.status_code != 200:
        raise Exception("Unexpected status code: " + str(r.status_code))

    return r


def process(session, config):
    r = get_update_links(session=session, config=config)

    root_node = etree.fromstring(r.text.encode('utf-8'))
    updatecheck_node = root_node.xpath('//response/app/updatecheck')[0]
    status = updatecheck_node.get('status')
    if status == 'noupdate':
        print("No update available.")
        return None
    if status != 'ok':
        raise Exception('/response/app/updatecheck has ' +
                        'unknown status attribute value')

    manifest_node = updatecheck_node.xpath('//manifest')[0]
    package_node = updatecheck_node.xpath('//manifest/packages/package')[0]
    name = package_node.get('name')
    safe_name = name.replace('/', '_')
    hash_sha256 = package_node.get('hash_sha256')
    expected_size = int(package_node.get('size'))

    if os.path.isfile(safe_name):
        print('"{}" exists. Skipping.'.format(safe_name))
        return None

    url_base = updatecheck_node.xpath('//urls/url')[0].get('codebase')
    url = url_base + ('' if url_base.endswith('/') else '/') + name

    print("Dowloading {}".format(url))
    print("expected size: {} bytes".format(expected_size))
    r = session.get(url, stream=True)

    if r.status_code != 200:
        raise Exception("Can't download update")

    content_length = int(r.headers.get('content-length'))
    if content_length != expected_size:
        raise Exception('Downloaded data size mismatch')

    content = b''
    chunk_size = 64 * 1024
    progress_bar_max = (content_length + chunk_size - 1)/chunk_size + 1
    for chunk in progress.bar(r.iter_content(chunk_size=chunk_size),
                              expected_size=progress_bar_max):
        if chunk:
            content += chunk

    if len(content) != expected_size:
        raise Exception('Downloaded data size mismatch')

    if hashlib.sha256(content).hexdigest() != hash_sha256:
        raise Exception('Downloaded data hash mistmatch')

    with open(safe_name + '.tmp', 'wb') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())

    with open(safe_name + '.sha256.tmp', 'wb') as f:
        f.write((hash_sha256 + '  ' + safe_name + '\n').encode('utf-8'))
        f.flush()
        os.fsync(f.fileno())

    os.rename(safe_name + '.tmp', safe_name)
    os.rename(safe_name + '.sha256.tmp', safe_name + '.sha256')


def download_all(session):
    for channel in ['stable', 'beta', 'dev', 'canary']:
        process(session,
                Config(app_id='mimojjlkmoijpicakmndhoigimigcmbb',
                       platform='Windows', arch='x86', channel=channel,
                       request_os='windows', request_arch='x86'))
        process(session,
                Config(app_id='mimojjlkmoijpicakmndhoigimigcmbb',
                       platform='Windows', arch='x86_64', channel=channel,
                       request_os='windows', request_arch='x64'))
        process(session,
                Config(app_id='mimojjlkmoijpicakmndhoigimigcmbb',
                       platform='Linux', arch='x86_64', channel=channel,
                       request_os='linux', request_arch='x64'))

    for channel in ['stable', 'beta', 'dev', 'canary']:
        process(session,
                Config(app_id='ckjlcfmdbdglblbjglepgnoekdnkoklc',
                       platform='Chrome OS', arch='x86_64', channel=channel,
                       request_os='cros', request_arch='x64'))
        process(session,
                Config(app_id='ckjlcfmdbdglblbjglepgnoekdnkoklc',
                       platform='Chrome OS', arch='arm', channel=channel,
                       request_os='cros', request_arch='arm'))
        process(session,
                Config(app_id='ckjlcfmdbdglblbjglepgnoekdnkoklc',
                       platform='Chrome OS', arch='arm64', channel=channel,
                       request_os='cros', request_arch='arm64'))


def download_cros_x86_64(session):
    process(session,
            Config(app_id='ckjlcfmdbdglblbjglepgnoekdnkoklc',
                   platform='Chrome OS', arch='x86_64', channel='canary',
                   request_os='cros', request_arch='x64'))


def main(args):
    session = requests.Session()
    if args.download_all:
        download_all(session)
    else:
        download_cros_x86_64(session)

if __name__ == '__main__':
    if sys.version_info[0] != 3:
        print("{} expects Python 3".format(sys.argv[0]))
        sys.exit(1)

    parser = argparse.ArgumentParser(description=
        'Download PepperFlash version from Chrome OS.')
    parser.add_argument('--all', dest='download_all', action='store_const',
                        const=True, default=False,
                        help='Download all known versions.')
    args = parser.parse_args()
    main(args)
