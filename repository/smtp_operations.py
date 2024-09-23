import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EmailSender:
    def __init__(self, smtp_server, smtp_port, from_email, to_email):
        """
        EmailSender sınıfını başlatır.

        :param smtp_server: SMTP sunucu adresi
        :param smtp_port: SMTP sunucu portu
        :param from_email: Gönderen e-posta adresi
        :param to_email: Alıcı e-posta adresi
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.from_email = from_email
        self.to_email = to_email

    def list_to_html_table(self, data_list):
        """
        Bir listeyi HTML tablosuna dönüştürür.
        Parametre olarak her bir elemanı dict olan bir liste alır.

        :param data_list: List[Dict], her elemanı bir dict olan liste
        :return: str, HTML tablo
        """
        if not data_list:
            return "<p>Veri yok</p>"

        # HTML tablo başlat
        html = '<table style="border: 1px solid #ddd; border-collapse: collapse; width: 100%;">'

        # Tablo başlıklarını al (Listenin ilk elemanındaki anahtarlar)
        headers = data_list[0].keys()

        # Tablo başlıklarını ekle (kalın - bold)
        html += '<tr>'
        for header in headers:
            html += f'<th style="border: 1px solid #ddd; padding: 8px; text-align: left; font-weight: bold;">{header}</th>'
        html += '</tr>'

        # Her bir satırı ekle
        for row in data_list:
            html += '<tr>'
            for header in headers:
                html += f'<td style="border: 1px solid #ddd; padding: 8px; text-align: left;">{row[header]}</td>'
            html += '</tr>'

        # Tabloyu kapat
        html += '</table>'

        return html
    def send_email(self, subject, body_html):
        """
        HTML formatında e-posta gönderir.

        :param subject: E-posta başlığı
        :param body_html: E-posta HTML içeriği
        :return: None
        """
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = self.to_email
        msg['Subject'] = subject

        # E-posta gövdesi (HTML olarak)
        msg.attach(MIMEText(body_html, 'html'))

        try:
            # SMTP sunucusuna bağlan
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.sendmail(self.from_email, self.to_email, msg.as_string())
            print("E-posta başarıyla gönderildi!")

        except Exception as e:
            print(f"E-posta gönderimi başarısız oldu: {e}")

        finally:
            server.quit()  # Sunucu ile bağlantıyı kapat