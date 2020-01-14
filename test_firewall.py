from firewall import *
import unittest

class TestMethods(unittest.TestCase):
    def test_preprocess(self):
        fw = Firewall('rules.csv')
        self.assertEqual(['inbound', 'tcp', '80', '192.168.1.2'], fw.preprocess('inbound,tcp,80,192.168.1.2'))
        self.assertEqual(['inbound', 'udp', '53', '192.168.2.1'], fw.preprocess('inbound, udp, 53, 192.168.2.1'))
        self.assertEqual(['outbound', 'tcp', '10234', '192.168.10.11'], fw.preprocess('"outbound", tcp, 10234, "192.168.10.11"'))
        self.assertEqual(['inbound', 'udp', '24', '52.12.48.92'], fw.preprocess('inbound, udp, 24, 52.12.48.92'))
    
    def test_acceptance(self):
        fw = Firewall('rules.csv')
        self.assertTrue(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
        self.assertTrue(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
        self.assertTrue(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
        self.assertFalse(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
        self.assertFalse(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
        
if __name__ == "__main__":
    unittest.main()