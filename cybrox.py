import argparse
import os
import scapy.all as scapy
from datetime import datetime
import logging
import tensorflow as tf
from fpdf import FPDF
import json
import shutil
import cryptography
from cryptography.fernet import Fernet

# Suppress TensorFlow logging at all levels
import logging
tf.get_logger().setLevel(logging.ERROR)

# Additional suppression of absl logging (used by TensorFlow)
import absl.logging
absl.logging.set_verbosity(absl.logging.ERROR)
absl.logging.get_absl_handler().python_handler.stream = open(os.devnull, 'w')

# Setting up logging for forensic workflows
logging.basicConfig(
    filename='cybrox.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Encryption for data security
class DataSecurity:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt_data(self, data):
        logging.info("Encrypting acquired evidence data...")
        if isinstance(data, str):
            data = data.encode()
        encrypted_data = self.cipher_suite.encrypt(data)
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        logging.info("Decrypting evidence data...")
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        return decrypted_data.decode()

# Evidence Acquisition Class with Automated Acquisition and Encryption
class EvidenceAcquisition:
    def __init__(self):
        self.sources = []
        self.security = DataSecurity()

    def acquire_from_hard_drive(self, drive_path):
        logging.info(f"Starting evidence acquisition from hard drive: {drive_path}")
        if not os.path.exists(drive_path):
            logging.error(f"Path {drive_path} does not exist.")
            return {"status": "failed", "message": "Drive path does not exist"}
        # Simulate acquisition process
        data = "sample_hard_drive_data"
        encrypted_data = self.security.encrypt_data(data)
        return {"status": "success", "data": encrypted_data}

    def acquire_from_network(self):
        logging.info("Acquiring evidence from network traffic...")
        try:
            packets = scapy.sniff(count=10)
            packets.summary()
            return packets
        except Exception as e:
            logging.error(f"Network acquisition failed: {e}")
            return {"status": "failed", "message": "Network sniffing error"}

    def acquire_from_mobile_device(self, device_id):
        logging.info(f"Acquiring evidence from mobile device: {device_id}")
        data = "sample_mobile_data"
        encrypted_data = self.security.encrypt_data(data)
        return {"status": "success", "data": encrypted_data}

    def acquire_from_memory(self):
        logging.info("Acquiring evidence from memory dump...")
        # Simulate memory dump acquisition (normally would use tools like `volatility`)
        data = "sample_memory_data"
        encrypted_data = self.security.encrypt_data(data)
        return {"status": "success", "data": encrypted_data}

    def automate_acquisition(self, target_machines):
        logging.info(f"Automating evidence acquisition for machines: {target_machines}")
        for machine in target_machines:
            print(f"[INFO] Acquiring evidence from {machine}")
            # Simulate SSH-based acquisition
        return {"status": "success", "message": "Automated acquisition complete"}

# Automated Analysis Class with AI-based Malware Detection
class AutomatedAnalysis:
    def __init__(self):
        self.model = self.load_model()

    def load_model(self):
        logging.info("Loading AI-based malware detection model...")
        # Placeholder for loading a more sophisticated AI model
        model = tf.keras.Sequential([tf.keras.layers.Dense(10, activation='relu')])
        return model

    def detect_malware(self, data):
        logging.info("Running AI-based malware detection...")
        # Simulate AI-based malware detection with dummy input
        prediction = self.model.predict([[float(x) for x in data.split()]])
        return {"malware_detected": bool(prediction[0] > 0.5)}

    def file_carving(self, data):
        logging.info("Performing file carving...")
        carved_files = ["file1.txt", "file2.png"]
        return carved_files

    def advanced_analysis(self, data):
        logging.info("Performing advanced AI analysis...")
        # Simulate advanced AI-based analysis
        return {"status": "success", "data": "advanced_analysis_results"}

# Reporting and Workflow Integration Class with Custom Notes and Enhanced Summaries
class ReportGeneration:
    def __init__(self, report_name='cybrox_report.pdf'):
        self.report = FPDF()
        self.report_name = report_name

    def generate_report(self, evidence_summary, analysis_results, custom_notes=""):
        logging.info("Generating investigation report...")
        self.report.add_page()
        self.report.set_font("Arial", size=12)

        # Add timestamp and summary
        self.report.cell(200, 10, txt="Digital Forensics Investigation Report", ln=True)
        self.report.cell(200, 10, txt=f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        
        # Add evidence summary
        self.report.cell(200, 10, txt="Evidence Acquisition Summary", ln=True)
        self.report.multi_cell(200, 10, txt=json.dumps(evidence_summary, indent=4))

        # Add analysis results
        self.report.cell(200, 10, txt="Automated Analysis Results", ln=True)
        self.report.multi_cell(200, 10, txt=json.dumps(analysis_results, indent=4))

        # Add custom notes
        if custom_notes:
            self.report.cell(200, 10, txt="Investigator's Notes", ln=True)
            self.report.multi_cell(200, 10, txt=custom_notes)

        # Save report
        self.report.output(self.report_name)
        logging.info(f"Report generated: {self.report_name}")

# CLI Class with Additional Features
class CybroXCLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description='CybroX - Digital Forensics Command Line Interface')
        self.subparsers = self.parser.add_subparsers(dest='command')

        # Add commands
        self.add_evidence_commands()
        self.add_analysis_commands()
        self.add_report_commands()

    def add_evidence_commands(self):
        evidence_parser = self.subparsers.add_parser('acquire', help='Acquire evidence from various sources')
        evidence_parser.add_argument('source', choices=['hard_drive', 'network', 'mobile', 'memory', 'automate'], help='Specify source of evidence')
        evidence_parser.add_argument('--path', type=str, help='Path for hard drive acquisition')
        evidence_parser.add_argument('--device', type=str, help='Device ID for mobile acquisition')
        evidence_parser.add_argument('--machines', nargs='+', help='List of target machines for automated acquisition')

    def add_analysis_commands(self):
        analysis_parser = self.subparsers.add_parser('analyze', help='Perform automated analysis')
        analysis_parser.add_argument('type', choices=['malware', 'file_carving', 'advanced'], help='Type of analysis')
        analysis_parser.add_argument('--data', type=str, help='Data for analysis')

    def add_report_commands(self):
        report_parser = self.subparsers.add_parser('report', help='Generate investigation report')
        report_parser.add_argument('--evidence', type=str, help='Path to evidence summary file')
        report_parser.add_argument('--analysis', type=str, help='Path to analysis results file')
        report_parser.add_argument('--notes', type=str, help='Investigator’s custom notes for the report')

    def run(self):
        args = self.parser.parse_args()
        acquisition = EvidenceAcquisition()
        analysis = AutomatedAnalysis()
        report_gen = ReportGeneration()

        if args.command == 'acquire':
            if args.source == 'hard_drive' and args.path:
                result = acquisition.acquire_from_hard_drive(args.path)
            elif args.source == 'network':
                result = acquisition.acquire_from_network()
            elif args.source == 'mobile' and args.device:
                result = acquisition.acquire_from_mobile_device(args.device)
            elif args.source == 'memory':
                result = acquisition.acquire_from_memory()
            elif args.source == 'automate' and args.machines:
                result = acquisition.automate_acquisition(args.machines)
            logging.info(result)
            print(result)

        elif args.command == 'analyze':
            if args.type == 'malware':
                result = analysis.detect_malware(args.data)
            elif args.type == 'file_carving':
                result = analysis.file_carving(args.data)
            elif args.type == 'advanced':
                result = analysis.advanced_analysis(args.data)
            logging.info(result)
            print(result)

        elif args.command == 'report':
            evidence_summary = json.loads(args.evidence) if args.evidence else {}
            analysis_results = json.loads(args.analysis) if args.analysis else {}
            custom_notes = args.notes if args.notes else ""
            report_gen.generate_report(evidence_summary, analysis_results, custom_notes)
            print("Report generated.")

# Fixing __name__ == "__main__" check
if __name__ == "__main__":
    CybroXCLI().run()
