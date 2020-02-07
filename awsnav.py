#!/usr/bin/env python

"""
AWS Navigator -- web based tool to navigate across AWS ECS entities.
"""

import argparse
import BaseHTTPServer
import datetime
import json
import logging
import re
import SocketServer
import subprocess
import sys
import traceback
import urlparse


# Default settings
DEF_BINDADDR = "0.0.0.0"
DEF_BINDPORT = 9000

LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

LOGGER = None


def main():
    """Entry point"""
    global LOGGER  # pylint: disable=global-statement
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='AWS Navigator -- web based tool to navigate '
        'across AWS ECS entities.')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Be much verbose.')
    parser.add_argument(
        '--bindaddr',
        help='IP address used by HTTP server to listen'
        ' for incoming connections.'
        ' Default is %r' % DEF_BINDADDR)
    parser.add_argument(
        '--bindport', type=int,
        help='TCP port number used by RESTful server to listen'
        ' for incoming connections.'
        ' Default is %r' % DEF_BINDPORT)
    args = parser.parse_args()
    loglevel = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        level=loglevel)
    LOGGER = logging.getLogger('awsnav')
    try:
        start_server(bindaddr=args.bindaddr, bindport=args.bindport)
    except KeyboardInterrupt:
        logging.getLogger().info('interrupted by user (^C)')
        sys.exit(1)
    except Exception:  # pylint: disable=broad-except
        logging.getLogger().critical('Abnormal termination', exc_info=True)
        sys.exit(1)


def start_server(bindaddr=None, bindport=None):
    """Start HTTP server and serve forever."""
    # Apply defaults
    if bindaddr is None:
        bindaddr = DEF_BINDADDR
    if bindport is None:
        bindport = DEF_BINDPORT
    LOGGER.info('starting at %s:%r...', bindaddr, bindport)
    # start httpd
    rest_server = ANServer(bindaddr, bindport)
    rest_server.serve_forever()


class RepliedException(Exception):
    """
    Raised when request processing is done and there is nothing to do more.
    """
    pass


class ANServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    """HTTP Server."""
    def __init__(self, addr, port):
        self.bindaddr = addr
        self.bindport = port
        BaseHTTPServer.HTTPServer.__init__(self, (addr, port), ANHandler)


class ANHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """HTTP Request Handler."""

    def do_GET(self):  # pylint: disable=invalid-name
        """
        Wrapper for the process_unsafe() method which catches all
        raised exceptions and logs them.
        The method is vital because standard implementation of
        BaseHTTPServer.BaseHTTPRequestHandler silently drops all
        exceptions raised during HTTP request processing.
        """
        try:
            try:
                self.process_unsafe()
            except RepliedException:
                pass
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.error('Crashed', exc_info=True)
                self.reply_with_error(exc)
        except RepliedException:  # reply already sent
            pass

    def process_unsafe(self):
        """HTTP request processing entry point."""
        parsed = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(parsed.query)
        # URL path router
        path = parsed.path.strip('/')
        if path == '':
            self.reply_with_html('Clusters', gen_clusters())
        elif path == 'ping':
            self.send_response(204)
            self.end_headers()
            raise RepliedException
        elif path == 'cluster':
            cid = query['cid'][0]
            self.reply_with_html('Cluster: ' + cid, gen_cluster(cid))
        elif path == 'service':
            cid, sid = [query[k][0] for k in ['cid', 'sid']]
            self.reply_with_html('Service: ' + sid,
                                 gen_service(cid, sid))
        elif path == 'task':
            cid, sid, tid = [query[k][0] for k in ['cid', 'sid', 'tid']]
            self.reply_with_html('Task: ' + tid,
                                 gen_task(cid, sid, tid))
        elif path == 'taskDefinition':
            cid, sid, tdid = [query[k][0] for k in ['cid', 'sid', 'tdid']]
            self.reply_with_html('Task Definition: ' + tdid,
                                 gen_task_def(cid, sid, tdid))
        elif path == 'containerInstance':
            cid, ciid = [query[k][0] for k in ['cid', 'ciid']]
            self.reply_with_html('Container instance: ' + ciid,
                                 gen_cinstance(cid, ciid))
        elif path == 'instance':
            iid = query['iid'][0]
            self.reply_with_html('EC2 Instance: ' + iid,
                                 gen_instance(iid))
        self.send_error(404)

    def reply_with_html(self, title, content, status=200):
        """
        Reply to the client with HTML page.

        :param title: page main title
        :type title: string

        :param content: contents of the <body> HTML tag.
        :type content: string

        :param status: HTTP status code
        :type status: int
        """
        content = """<!DOCTYPE html>
        <html>
          <head>
            <meta charset='utf-8'>
            <title>{}</title>
            <meta name="viewport"
                  content="width=device-width, initial-scale=1.0">
          </head>
          <body>
            [&nbsp;<a href="/">home</a>&nbsp;]
            <h1>{}</h1>{}</body>
        </html>
        """.format(title, title, content)
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)
        raise RepliedException

    def reply_with_error(self, exc):
        """
        Send HTML page with crash report to the client.

        :param exc: exception occured
        :type exc: Exception
        """
        data = '<pre>{}</pre>'.format(traceback.format_exc(exc))
        self.reply_with_html('501: Crashed', data, 501)

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """
        Override the BaseHTTPServer.BaseHTTPRequestHandler.log_message().
        There is no stdout in daemonized state so relay messages
        to the 'logging' facility.
        """
        LOGGER.info(format, *args)

    def send_error(self, code, message=None):
        """
        Override for BaseHTTPServer.BaseHTTPRequestHandler.send_error().
        """
        BaseHTTPServer.BaseHTTPRequestHandler.send_error(self, code, message)
        raise RepliedException


def gen_clusters():
    """Generate contents of ECS Clusters page"""
    items = awscli('ecs', 'list-clusters')
    items = items['clusterArns']
    return linklist('Entries', '/cluster?cid={}', [[e] for e in items])


def gen_cluster(cid):
    """Generate contents of ECS Cluster page"""
    data = awscli('ecs', 'describe-clusters', '--clusters', cid)
    data = data['clusters'][0]
    srvs = awscli('ecs', 'list-services', '--cluster', cid)
    srvs = srvs['serviceArns']
    return (gen_details(data)
            + linklist('Services', '/service?cid={}&sid={}',
                       [[cid, e] for e in srvs]))


def gen_service(cid, sid):
    """Generate contents of ECS Service page"""
    service = awscli('ecs', 'describe-services', '--cluster', cid,
                     '--services', sid)
    service = service['services'][0]
    tdid = service['taskDefinition']
    tasks = awscli('ecs', 'list-tasks', '--cluster', cid,
                   '--service-name', service['serviceName'])
    tasks = tasks['taskArns']
    return (gen_parents(('cluster', [('cid', cid)], cid))
            + gen_related(('taskDefinition',
                           [('cid', cid),
                            ('sid', sid),
                            ('tdid', tdid)], tdid))
            + linklist('Tasks', '/task?cid={}&sid={}&tid={}',
                       [[cid, sid, e] for e in tasks])
            + gen_details(service))


def gen_task(cid, sid, tid):
    """Generate contents of ECS Task page"""
    task = awscli('ecs', 'describe-tasks', '--cluster', cid,
                  '--tasks', tid)
    task = task['tasks'][0]
    ciid = task['containerInstanceArn']
    tdid = task['taskDefinitionArn']
    # fetch information about EC2 instance which hosts the task
    cinst = awscli('ecs', 'describe-container-instances',
                   '--cluster', cid, '--container-instances', ciid)
    cinst = cinst['containerInstances'][0]
    iid = cinst['ec2InstanceId']
    instance = awscli('ec2', 'describe-instances', '--instance-ids', iid)
    instance = instance['Reservations'][0]['Instances'][0]
    pub_ip = instance.get('PublicIpAddress', '')
    priv_ip = instance.get('PrivateIpAddress', '')
    inst_type = instance.get('InstanceType', '')
    return (gen_parents(('cluster', [('cid', cid)], cid),
                        ('service', [('cid', cid), ('sid', sid)], sid))
            + gen_related(('containerInstance',
                           [('cid', cid), ('ciid', ciid)], ciid),
                          ('taskDefinition',
                           [('cid', cid),
                            ('sid', sid),
                            ('tdid', tdid)], tdid),
                          ('instance', [('iid', iid)], iid))
            + gen_extra_info(('Host system public IP', pub_ip),
                             ('Host system private IP', priv_ip),
                             ('Host system instance type', inst_type))
            + gen_details(task))


def gen_task_def(cid, sid, tdid):
    """Generate contents of ECS Task Definition page"""
    task_def = awscli('ecs', 'describe-task-definition',
                      '--task-definition', tdid)
    task_def = task_def['taskDefinition']
    return (gen_parents(('cluster', [('cid', cid)], cid),
                        ('service', [('cid', cid), ('sid', sid)], sid))
            + gen_details(task_def))


def gen_cinstance(cid, ciid):
    """Generate contents of ECS Container Instance page"""
    cinst = awscli('ecs', 'describe-container-instances',
                   '--cluster', cid, '--container-instances', ciid)
    cinst = cinst['containerInstances'][0]
    iid = cinst['ec2InstanceId']
    return (gen_parents(('cluster', [('cid', cid)], cid),
                        ('instance', [('iid', iid)], iid))
            + gen_details(cinst))


def gen_instance(iid):
    """Generate contents of EC2 Instance page"""
    instance = awscli('ec2', 'describe-instances', '--instance-ids', iid)
    instance = instance['Reservations'][0]['Instances'][0]
    return gen_details(instance)


def linklist(title, href_fmt, args):
    """Generate unordered list of links"""
    href_fmt = '<li><a href="{}">{}</a>'.format(href_fmt, '{}')
    entries = [href_fmt.format(*(e + [e[-1]])) for e in sorted(args)]
    fmt = '<h2>{} ({} found)</h2><ul>{}</ul>'
    return fmt.format(title, len(entries), ''.join(entries))


def gen_related(*related):
    """Generate section with list of related objects"""
    fmt = '<li>{}: <a href="/{}?{}">{}</a>'
    data = [fmt.format(r[0], r[0],
                       '&'.join(['='.join(e) for e in r[1]]),
                       r[2])
            for r in related]
    return '<h2>Related objects</h2><ul>{}</ul>'.format(''.join(data))


def gen_parents(*parents):
    """Generate section with list of parent objects"""
    fmt = '<li>{}: <a href="/{}?{}">{}</a>'
    data = [fmt.format(p[0], p[0],
                       '&'.join(['='.join(e) for e in p[1]]),
                       p[2])
            for p in parents]
    return '<h2>Parent objects</h2><ul>{}</ul>'.format(''.join(data))


def gen_extra_info(*entries):
    """Generate extra information section"""
    if not entries:
        return ''
    entries = ''.join(['<tr><td><b>{}</b><td>{}'.format(k, v)
                       for k, v in entries if v != ''])
    return ('<h2>Information</h2>'
            + '<table border=1>{}</table>'.format(entries))


def gen_details(details):
    """Generate section with entity details"""
    fmt = '<h2>Details</h2><pre>{}</pre>'
    tooltip_fmt = '<abbr title="{}">{}</abbr>'
    data = json.dumps(details, indent=2)
    pattern = '[^0-9](1[0-9]{9,9}(\\.[0-9]+)?)'
    timestamps = []
    for match in re.finditer(pattern, data):
        t_str = match.group(1)
        t_float = float(t_str)
        timestamps.append([t_str, t_float])
    for t_str, t_float in timestamps:
        t_human = datetime.datetime.utcfromtimestamp(t_float).\
            strftime('%Y-%m-%d %H:%M:%S UTC')
        data = data.replace(t_str, tooltip_fmt.format(t_human, t_str))
    return fmt.format(data)


def awscli(*args):
    """
    Call aws cli tool, return parsed JSON document.

    :param args: aws cli command line arguments
    :type args: list of string

    :rtype: dict
    """
    args = ['aws', '--output', 'json'] + list(args)
    LOGGER.debug("running AWS CLI as: %r", args)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr:
        LOGGER.debug("STDERR: %r", stderr)
    return json.loads(stdout)


if __name__ == '__main__':
    main()
