from bcc import BPF #1
from bcc.utils import printb
from pylibpcap import OpenPcap
import time
import struct
import socket
#import ctypes as ct
import sys

from PyQt5.QtCore import QObject, pyqtSignal, QEventLoop, QTimer
from PyQt5.QtWidgets import QMainWindow, QPushButton, QApplication, QTextEdit
from PyQt5.QtGui import QTextCursor



b = BPF(src_file="net.c") #3
fn = b.load_func("net_filter", BPF.XDP) #4
b.attach_xdp("ens33", fn, 0) #5


def print_recv_pkg(cpu, data, size):
    event = b["unix_recv_events"].event(data)
    print("\n----------------", end="")
    for i in range(0, event.recv_len-1):
        
        print("%02x " %event.pkt[i], end="")
        #sys.stdout.flush()
        if (i+1)%16 == 0:
            print("")
            print("----------------", end="")
    print("\n----------------recv %d bytes" % event.recv_len)
    #print('\npid:%d tgid:%d task:%s'%(event.pid,event.tgid,event.comm))
    print("proto:%d" % event.proto)  
    print("smac:", end="")
    for i in range(0,5):
    	print("%02x"%event.smac[i], end="")
    print("   dmac:", end="")
    for i in range(0,5):
    	print("%02x"%event.dmac[i], end="")
    if event.sport !=0:
    	print("\nsport:%d    dport:%d" % (event.sport,event.dport))
    if event.saddr !=0:
    	print("saddr:%s" % socket.inet_ntoa(struct.pack('I',socket.htonl(event.saddr))))
    if event.daddr !=0:
    	print("daddr:%s" % socket.inet_ntoa(struct.pack('I',socket.htonl(event.daddr))))

b["unix_recv_events"].open_ring_buffer(print_recv_pkg)


class Stream(QObject):
    """Redirects console output to text widget."""
    newText = pyqtSignal(str)
 	
    def write(self, text):
        self.newText.emit(str(text))

def onUpdateText(text):
        """Write console output to text widget."""
        cursor = process.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        process.setTextCursor(cursor)
        process.ensureCursorVisible()
 
def closeEvent( event):
        """Shuts down application on close."""
        # Return stdout to defaults.
        sys.stdout = sys.__stdout__


def genMastClicked():
        """Runs the main function."""
        print('Running...')






       
 
app = QApplication(sys.argv)
app.aboutToQuit.connect(app.deleteLater)

widget = QMainWindow()
btnGenMast = QPushButton('Run', widget)
btnGenMast.move(450, 50)
btnGenMast.resize(100, 200)
btnGenMast.clicked.connect(genMastClicked)
 
        # Create the text output widget.
process = QTextEdit(widget, readOnly=True)
process.ensureCursorVisible()
process.setLineWrapColumnOrWidth(500)
process.setLineWrapMode(QTextEdit.FixedPixelWidth)
process.setFixedWidth(800)
process.setFixedHeight(700)
process.move(30, 50)
sys.stdout = Stream(newText=onUpdateText)
        # Set window size and title, then show the window.
widget.setGeometry(300, 300, 1000, 900)
widget.setWindowTitle('流量分析')
widget.show()





try:
    while 1:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    b.remove_xdp("ens33", 0) 
    
    
sys.exit(app.exec_())






