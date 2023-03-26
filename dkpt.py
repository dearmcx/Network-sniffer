import sys
import time
import pcap
import dpkt
from PyQt5.QtCore import QObject, pyqtSignal, QEventLoop, QTimer
from PyQt5.QtWidgets import QMainWindow, QPushButton, QApplication, QTextEdit
from PyQt5.QtGui import QTextCursor
 
 
'''
将抓包解析结果输出定向到Qtextedit中
'''
 
 
class Stream(QObject):
    """Redirects console output to text widget."""
    newText = pyqtSignal(str)
 
    def write(self, text):
        self.newText.emit(str(text))
 
 
class GenMast(QMainWindow):
    """Main application window."""
    def __init__(self):
        super().__init__()
 
        self.initUI()
 
        # Custom output stream.
        sys.stdout = Stream(newText=self.onUpdateText)
 
    def onUpdateText(self, text):
        """Write console output to text widget."""
        cursor = self.process.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.process.setTextCursor(cursor)
        self.process.ensureCursorVisible()
 
    def closeEvent(self, event):
        """Shuts down application on close."""
        # Return stdout to defaults.
        sys.stdout = sys.__stdout__
        super().closeEvent(event)
 
    def initUI(self):
        """Creates UI window on launch."""
        # Button for generating the master list.
        btnGenMast = QPushButton('Run', self)
        btnGenMast.move(450, 50)
        btnGenMast.resize(100, 200)
        btnGenMast.clicked.connect(self.genMastClicked)
 
        # Create the text output widget.
        self.process = QTextEdit(self, readOnly=True)
        self.process.ensureCursorVisible()
        self.process.setLineWrapColumnOrWidth(500)
        self.process.setLineWrapMode(QTextEdit.FixedPixelWidth)
        self.process.setFixedWidth(400)
        self.process.setFixedHeight(200)
        self.process.move(30, 50)
 
        # Set window size and title, then show the window.
        self.setGeometry(300, 300, 600, 300)
        self.setWindowTitle('IP包流量分析')
        self.show()
 
    def grabpackage(self):
        # 所有网络接口
        devs = pcap.findalldevs()
        print('All NIC:',devs, sep='\n')
        # 抓包
        sniffer = pcap.pcap(name='ens33', promisc=True, immediate=True)
 
        num = 0  # 控制解析包显示数量
 
        # 解析: timestamp(时间戳)，raw_buf(包中原始数据)
        for timestamp, raw_buf in sniffer:
            # 解析以太网帧
            eth = dpkt.ethernet.Ethernet(raw_buf)
            # 判断是否为IP数据报
            if not isinstance(eth.data, dpkt.ip.IP):
                print("Non IP packet type not supported ", eth.data.__class__.__name__)
                continue
            # 抓IP数据包
            packet = eth.data
 
            # 取出分片信息
            df = bool(packet.off & dpkt.ip.IP_DF)
            mf = bool(packet.off & dpkt.ip.IP_MF)
            offset = packet.off & dpkt.ip.IP_OFFMASK
 
            # 输出数据包信息：time,src,dst,protocol,length,ttl,df,mf,offset,checksum
            output1 = {'time': time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(timestamp)))}
            output2 = {'src': '%d.%d.%d.%d' % tuple(packet.src), 'dst': '%d.%d.%d.%d' % tuple(packet.dst)}
            output3 = {'protocol': packet.p, 'len': packet.len, 'ttl': packet.ttl}
            output4 = {'df': df, 'mf': mf, 'offset': offset, 'checksum': packet.sum}
            print()
            print(output1)
            print(output2)
            print(output3)
            print(output4)
 
            num = num+1
            if num == 10:
                break
 
    def genMastClicked(self):
        """Runs the main function."""
        print('Running...')
 
        self.grabpackage()
 
        loop = QEventLoop()
        QTimer.singleShot(2000, loop.quit)
        loop.exec_()
 
        print('Done.')
 
 
if __name__ == '__main__':
    # Run the application.
    app = QApplication(sys.argv)
    app.aboutToQuit.connect(app.deleteLater)
    gui = GenMast()
    sys.exit(app.exec_())
