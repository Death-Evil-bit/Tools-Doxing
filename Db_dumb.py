# extract/db_dumper.py
import json
import csv
import sqlite3
from datetime import datetime

class DBDumper:
    def __init__(self, proxy_rotator=None):
        self.proxy_rotator = proxy_rotator
        
    def save_to_json(self, data, filename):
        """Save extracted data to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving JSON: {e}")
            return False
    
    def save_to_csv(self, data, filename):
        """Save extracted data to CSV file"""
        if not data:
            return False
        
        try:
            # Get all fieldnames
            fieldnames = set()
            for row in data:
                fieldnames.update(row.keys())
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=list(fieldnames))
                writer.writeheader()
                writer.writerows(data)
            
            return True
        except Exception as e:
            print(f"Error saving CSV: {e}")
            return False
    
    def save_to_sqlite(self, data, table_name, db_file='school_data.db'):
        """Save extracted data to SQLite database"""
        if not data:
            return False
        
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Create table
            columns = list(data[0].keys())
            columns_def = ', '.join([f'"{col}" TEXT' for col in columns])
            create_table_sql = f'CREATE TABLE IF NOT EXISTS "{table_name}" ({columns_def})'
            
            cursor.execute(create_table_sql)
            
            # Insert data
            for row in data:
                placeholders = ', '.join(['?' for _ in columns])
                values = [row.get(col, '') for col in columns]
                insert_sql = f'INSERT INTO "{table_name}" VALUES ({placeholders})'
                cursor.execute(insert_sql, values)
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error saving to SQLite: {e}")
            return False
    
    def organize_student_data(self, raw_data):
        """Organize raw data into structured student information"""
        students = []
        
        for table_name, table_data in raw_data.items():
            for row in table_data:
                student = {}
                
                # Extract NIS/NISN
                for key, value in row.items():
                    key_lower = key.lower()
                    value_str = str(value)
                    
                    if 'nis' in key_lower or 'id' in key_lower:
                        if value_str.isdigit() and len(value_str) > 5:
                            student['nis'] = value_str
                    
                    if 'nama' in key_lower or 'name' in key_lower:
                        student['nama'] = value_str
                    
                    if 'alamat' in key_lower or 'address' in key_lower:
                        student['alamat'] = value_str
                    
                    if 'telp' in key_lower or 'phone' in key_lower:
                        student['telepon'] = value_str
                    
                    if 'kelas' in key_lower or 'class' in key_lower:
                        student['kelas'] = value_str
                    
                    if 'jurusan' in key_lower or 'major' in key_lower:
                        student['jurusan'] = value_str
                
                if student:
                    students.append(student)
        
        return students
    
    def organize_teacher_data(self, raw_data):
        """Organize raw data into structured teacher information"""
        teachers = []
        
        for table_name, table_data in raw_data.items():
            for row in table_data:
                teacher = {}
                
                for key, value in row.items():
                    key_lower = key.lower()
                    value_str = str(value)
                    
                    if 'nip' in key_lower or 'id' in key_lower:
                        teacher['nip'] = value_str
                    
                    if 'nama' in key_lower or 'name' in key_lower:
                        teacher['nama'] = value_str
                    
                    if 'mapel' in key_lower or 'subject' in key_lower:
                        teacher['mata_pelajaran'] = value_str
                    
                    if 'email' in key_lower:
                        teacher['email'] = value_str
                
                if teacher:
                    teachers.append(teacher)
        
        return teachers
    
    def generate_report(self, extracted_data, output_dir='reports'):
        """Generate comprehensive report of extracted data"""
        import os
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        report = {
            'generated_date': datetime.now().isoformat(),
            'summary': {},
            'data_types': {}
        }
        
        # Organize by data type
        student_data = self.organize_student_data(extracted_data)
        teacher_data = self.organize_teacher_data(extracted_data)
        
        report['summary']['total_tables'] = len(extracted_data)
        report['summary']['total_students'] = len(student_data)
        report['summary']['total_teachers'] = len(teacher_data)
        
        # Save organized data
        if student_data:
            self.save_to_json(student_data, f'{output_dir}/students.json')
            self.save_to_csv(student_data, f'{output_dir}/students.csv')
            report['data_types']['students'] = len(student_data)
        
        if teacher_data:
            self.save_to_json(teacher_data, f'{output_dir}/teachers.json')
            self.save_to_csv(teacher_data, f'{output_dir}/teachers.csv')
            report['data_types']['teachers'] = len(teacher_data)
        
        # Save full report
        report_file = f'{output_dir}/extraction_report.json'
        self.save_to_json(report, report_file)
        
        # Print summary
        print(f"\n[📊] EXTRACTION REPORT")
        print("="*40)
        print(f"Total tables extracted: {report['summary']['total_tables']}")
        print(f"Student records: {report['summary']['total_students']}")
        print(f"Teacher records: {report['summary']['total_teachers']}")
        print(f"Report saved to: {report_file}")
        print("="*40)
        
        return report
