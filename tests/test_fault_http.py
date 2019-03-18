import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/fault_http.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_truncated_request_method():
    assert packets[0].http.request_method == 'HEAD'


def test_truncated_request_uri():
    uri = ('/?ch=yRWrHfuVE4LJHedPND3onmG6bT-KEnaH5BTD7zyXqZoHLCrA'
           '2cwgzGOfypPKDZoT2z-fsSU84zOX8oyBKN0UJumnBsrStW5PPz7p5'
           'tl394HJxn5zQnq0CFFknIUu3fpSCh-AnZMQ3NcgyrdB&ac=isZdkJ'
           'EgKw8iEnGvDJaFQhI96Z4Oz6NoEF7oLSIyHTs3OsfPpIAhEL4dZFs'
           'rI2unrwdqh4BJHg93_vVi632eADQ9T3t1HSF4JtEsywPl2MaLrCB5'
           'Jf-Q9EgevFVZ9-E8K0i52caG-QWLtP5a0iEyfDHIUMZp4AnuOZ21w'
           'AsdLrGkngHf3rKXXeVqJA8eBqMeIsnvTz6_UnZyUBbbyta_Es1SHO'
           '55S-boR3U3t8lnjZdzw27LTot3wEj7ccuxHIqYIAgqkKJyyUUbFdc'
           'WHJTKB4_WeiyK3V0r8ARWhDCv1YjqhD4itQWpWSewaYrIdZCC9JF8'
           'sUMM8Z5xAl5BjpG9SlkOYQKFdPEK5BxVfc_BTH9e36Q1mnVmF3LJ6'
           'td1isnodzRTv3BbmzllklhRcurQU01mtKqw8ndm-wMeqV5znZpTGi'
           'F4bSOjeJ3VuSBGWoBGyTcMB2r3C4VJrtXjce_qvB5KIToi3dOskp3'
           'hZPGFYLOaV-KFcH5dHb_90odPiwtoaQ9TR57UiVwGA7irc6HK7CSz'
           'xlp-6_fNvt4wm5J_MO_Kc1Ku8YleZxWFpDYu6fB8yzO6af3hGLpwg'
           'UrCzc1jkVX82OQpbzUhps6YZ5bBnuqV_-bQpAzMhbaFpqhKs547o0'
           'iCYMrgjTe14R0I8OEl9x2PDYV_BPyeKcDt33S3jUzNBMjursXkPph'
           '4Oqv4dUW2nxJ3hlvebD9_k-z2yzxp_rUqj_Tv9IH75MqqsiwaKhh_'
           'MdZRswq_Pj0a_rZaYh66lfWBQv0VO_m4YjJmGl0hRETi3C_xec2EB'
           'XNonWg0fBLMFGAsrUucR_6OQhKP8Il_pv15tBnS7HiJusgs11LiW_'
           'wTZohfMsi9X0K__9o05jSCWt7QJ-h2WzJNXOeBXdDScw1HDZtBC84'
           'rcaoT8gm-jqYbvkAmWkOspXv7btuQ0aLC1Su_8W5dSB92TRsdkj5S'
           'MTjmlZTeGTFdAJcRtqDa5zMVofK5dkhve1c9LJDVc2LIGTb9gnzx8'
           'C596rE9P6U2rIVlCAXES7Nx&tr=VeXM98qkMaOxy3lCmTrIHMHWvE'
           'BXJgwM2mf-mFM-DC0brtGHnQ3z3ajaIWgXvisgBUa5L8fMB0k4clY'
           'iuwTHuwADGTd0nUccTThZToAHDjjXePkMNjQCZwB9rLbQKRo3hryw'
           'rQ6FZ9FfuFU3M3Ge3AdpGS1wrZOcAQE3jPRR0gLHaUZy3mNwk4h20'
           'AsSTsLxeqEzYTIUdpclueusvId_KVh6ki_wC14YVit33iEIkzDItR'
           'CDOeRM6RS6a3iX8qQR4GfKXB')
    assert packets[0].http.request_uri == uri
