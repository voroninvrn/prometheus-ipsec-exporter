#!/usr/bin/python3

import subprocess
import glob
import re
import vici
import multiprocessing
import collections
import time
from sys import exit
from flask import Flask, Response
from prometheus_client import Gauge, generate_latest
import prometheus_client as prom
import os
import time
import argparse as ap
from re import search

class VState(object):
    """holds the VPN state"""
    def __init__(self):
        self.alive = True
        self.session = vici.Session()
        self.possible_connections = []


class IpsecExporter:
    def __init__(self,  queue = None):
        self.state = VState()
        self.connections = self.get_possible_connections()
     
        self.app = Flask(__name__)
        self.state = VState()

        self.gauge = Gauge("ipsec_tunnel_status", "Output from the charon.vici socket", ["connection_name"])
        self.gauge2 = Gauge("ipsec_tunnel_in_bytes", "Output from the charon.vici socket", ["connection_name"])
        self.gauge3 = Gauge("ipsec_tunnel_out_bytes", "Output from the charon.vici socket", ["connection_name"])
        self.run_webserver()

    def get_possible_connections(self):
        ''' get all connections '''
        state = self.state
        state.possible_connections = []
        for conn in state.session.list_conns():
            for key in conn:
                state.possible_connections.append(key)

        return state.possible_connections

    def get_active_connections(self):
        ''' get active connections '''
        state = self.state
        state.active_connections = []
        for conn in state.session.list_sas():
            for key in conn:
                state.active_connections.append(key)

        return state.active_connections

    def serve_metrics(self):
        "Main method to serve the metrics."
        connections = self.connections
        gauge = self.gauge
        gauge2 = self.gauge2
        gauge3 = self.gauge3

        @self.app.route("/metrics")
        def metrics():
            """
            Flask endpoint to expose the prometheus metrics. With every request
            it gets, it executes the 'check_ipsec' command.
            """
            state = self.state
            activeconn = self.get_active_connections()
            for conn in connections:
                if conn in activeconn:
                     gauge.labels(conn).set('1')

                     for vpn_conn in state.session.list_sas():
                         for key in vpn_conn:
                             try:
                                 child = vpn_conn[key]['child-sas']
                                 if child == {}:
                                     child = None
                             except:
                       #       print ('tunnel not connected at child level!')
                                     child = None
                             if child is not None:
                            #     print (child)
                                 for child_key in child:
                                     if search(key, child_key):
            #                         print ('time: ', time.time(), 'child key', child_key, 'bytes-in', child[child_key]['bytes-in'], 'bytes-out', child[child_key]['bytes-out'])

                               #      print ('in: ', child[child_key]['bytes-in'])
                                       in_bytes = child[child_key]['bytes-in']
                                       in_bytes = float(str(in_bytes, 'utf-8'))
                                  #  print ('out: ', child[child_key]['bytes-out'])
                                       out_bytes = child[child_key]['bytes-out']
                                       out_bytes = float(str(out_bytes, 'utf-8'))
                                       
                                       gauge2.labels(key).set(in_bytes)
                                       gauge3.labels(key).set(out_bytes)
                else:                                                  
                     gauge.labels(conn).set('0')

            metrics = generate_latest()

            return Response(metrics, mimetype='text/plain', content_type='text/plain; charset=utf-8')

    def run_webserver(self):
        "Start the web application."
        self.serve_metrics()
        self.app.run(
            port="9000",
            host="0.0.0.0",
            use_reloader=False,
            debug=True
        )


if __name__ == "__main__":
    IpsecExporter()
