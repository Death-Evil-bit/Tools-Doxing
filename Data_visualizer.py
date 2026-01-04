#!/usr/bin/env python3
# analyze/data_visualizer.py - Data Visualization Module
import json
import csv
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import os

class DataVisualizer:
    def __init__(self, output_dir='visualizations'):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
    
    def load_student_data(self, json_file):
        """Load student data from JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except:
            return []
    
    def load_teacher_data(self, json_file):
        """Load teacher data from JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except:
            return []
    
    def plot_student_distribution(self, student_data, save=True):
        """Plot student class distribution"""
        if not student_data:
            print("[!] No student data to visualize")
            return None
        
        # Extract class information
        classes = {}
        for student in student_data:
            if isinstance(student, dict):
                kelas = student.get('kelas', student.get('class', 'Unknown'))
                if kelas:
                    if kelas in classes:
                        classes[kelas] += 1
                    else:
                        classes[kelas] = 1
        
        if not classes:
            print("[!] No class data found")
            return None
        
        # Sort classes
        sorted_classes = dict(sorted(classes.items()))
        
        # Create plot
        plt.figure(figsize=(12, 6))
        
        # Bar chart
        bars = plt.bar(sorted_classes.keys(), sorted_classes.values(), color='skyblue', edgecolor='black')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.title('Student Distribution by Class', fontsize=16, fontweight='bold')
        plt.xlabel('Class', fontsize=12)
        plt.ylabel('Number of Students', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save or show
        if save:
            filename = f"{self.output_dir}/student_distribution.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"[✓] Saved: {filename}")
            plt.close()
            return filename
        else:
            plt.show()
            return None
    
    def create_grade_chart(self, student_data, save=True):
        """Create grade distribution chart"""
        if not student_data:
            print("[!] No student data for grades")
            return None
        
        # Extract grade information
        grades = {}
        for student in student_data:
            if isinstance(student, dict):
                # Look for grade fields
                for key, value in student.items():
                    key_lower = key.lower()
                    if any(grade_word in key_lower for grade_word in ['nilai', 'grade', 'score']):
                        if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace('.', '').isdigit()):
                            try:
                                grade_val = float(value)
                                grade_range = self.get_grade_range(grade_val)
                                if grade_range in grades:
                                    grades[grade_range] += 1
                                else:
                                    grades[grade_range] = 1
                            except:
                                pass
        
        if not grades:
            # Try to find grade data in other fields
            grades = self.extract_grades_from_text(student_data)
        
        if not grades:
            print("[!] No grade data found")
            return None
        
        # Sort grade ranges
        grade_order = ['A (90-100)', 'B (80-89)', 'C (70-79)', 'D (60-69)', 'E (0-59)']
        sorted_grades = {k: grades.get(k, 0) for k in grade_order if k in grades}
        
        # Create pie chart
        plt.figure(figsize=(10, 8))
        
        colors = ['#4CAF50', '#8BC34A', '#FFC107', '#FF9800', '#F44336']
        explode = [0.05] * len(sorted_grades)
        
        wedges, texts, autotexts = plt.pie(
            sorted_grades.values(),
            labels=sorted_grades.keys(),
            colors=colors[:len(sorted_grades)],
            explode=explode,
            autopct='%1.1f%%',
            startangle=90,
            shadow=True
        )
        
        # Enhance text
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        plt.title('Grade Distribution', fontsize=16, fontweight='bold')
        plt.axis('equal')
        
        if save:
            filename = f"{self.output_dir}/grade_distribution.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"[✓] Saved: {filename}")
            plt.close()
            return filename
        else:
            plt.show()
            return None
    
    def get_grade_range(self, grade):
        """Convert numeric grade to letter range"""
        if grade >= 90:
            return "A (90-100)"
        elif grade >= 80:
            return "B (80-89)"
        elif grade >= 70:
            return "C (70-79)"
        elif grade >= 60:
            return "D (60-69)"
        else:
            return "E (0-59)"
    
    def extract_grades_from_text(self, student_data):
        """Extract grades from text fields"""
        grades = {}
        
        for student in student_data:
            if isinstance(student, dict):
                for value in student.values():
                    if isinstance(value, str):
                        # Look for grade patterns
                        grade_patterns = [
                            r'nilai\s*[:=]\s*(\d{2,3})',
                            r'grade\s*[:=]\s*([A-E])',
                            r'score\s*[:=]\s*(\d{2,3})',
                            r'(\d{2,3})\s*\/\s*100',  # 85/100
                            r'([A-E])\s*\(',  # A (Excellent)
                        ]
                        
                        for pattern in grade_patterns:
                            matches = re.findall(pattern, value, re.IGNORECASE)
                            for match in matches:
                                if match.isdigit():
                                    grade_val = int(match)
                                    grade_range = self.get_grade_range(grade_val)
                                    grades[grade_range] = grades.get(grade_range, 0) + 1
                                elif match in ['A', 'B', 'C', 'D', 'E']:
                                    grade_range = f"{match} (grade)"
                                    grades[grade_range] = grades.get(grade_range, 0) + 1
        
        return grades
    
    def generate_network_graph(self, relationships_data, save=True):
        """Generate relationship network graph"""
        # This is a simplified version
        # In real implementation, would use NetworkX
        
        print("[+] Generating simplified network visualization...")
        
        # Create a simple relationship matrix
        relationships = self.extract_relationships(relationships_data)
        
        if not relationships:
            print("[!] No relationship data found")
            return None
        
        plt.figure(figsize=(12, 10))
        
        # Create nodes
        nodes = list(set([r['source'] for r in relationships] + [r['target'] for r in relationships]))
        node_positions = {}
        
        # Circular layout
        import math
        center_x, center_y = 0.5, 0.5
        radius = 0.4
        
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / len(nodes)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node_positions[node] = (x, y)
            
            # Plot node
            plt.scatter(x, y, s=500, c='lightblue', edgecolors='black', zorder=2)
            plt.text(x, y, node, ha='center', va='center', fontsize=9, fontweight='bold')
        
        # Plot edges
        for rel in relationships:
            source = rel['source']
            target = rel['target']
            weight = rel.get('weight', 1)
            
            if source in node_positions and target in node_positions:
                x1, y1 = node_positions[source]
                x2, y2 = node_positions[target]
                
                # Draw line
                line = plt.plot([x1, x2], [y1, y2], 'gray', alpha=0.7, linewidth=weight*2)[0]
                
                # Add weight label
                mid_x = (x1 + x2) / 2
                mid_y = (y1 + y2) / 2
                plt.text(mid_x, mid_y, str(weight), fontsize=8, 
                        bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.7))
        
        plt.title('Relationship Network Graph', fontsize=16, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        
        if save:
            filename = f"{self.output_dir}/network_graph.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"[✓] Saved: {filename}")
            plt.close()
            return filename
        else:
            plt.show()
            return None
    
    def extract_relationships(self, data):
        """Extract relationships from data"""
        relationships = []
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    # Look for relationship indicators
                    for key, value in item.items():
                        key_lower = key.lower()
                        if any(rel_word in key_lower for rel_word in ['relasi', 'relation', 'hubungan', 'connection']):
                            if isinstance(value, str) and '->' in value:
                                parts = value.split('->')
                                if len(parts) == 2:
                                    relationships.append({
                                        'source': parts[0].strip(),
                                        'target': parts[1].strip(),
                                        'weight': 1
                                    })
        
        # If no explicit relationships, create some from data structure
        if not relationships and isinstance(data, list) and len(data) > 0:
            # Create teacher-student relationships based on classes
            for item in data[:10]:  # Limit for demo
                if isinstance(item, dict):
                    if 'nama' in item and 'kelas' in item:
                        relationships.append({
                            'source': 'Teacher',
                            'target': item['nama'],
                            'weight': 1
                        })
        
        return relationships[:20]  # Limit relationships
    
    def create_timeline_chart(self, timeline_data, save=True):
        """Create timeline of events"""
        if not timeline_data:
            print("[!] No timeline data")
            return None
        
        plt.figure(figsize=(14, 8))
        
        # Parse dates
        events = []
        for event in timeline_data:
            if isinstance(event, dict):
                date_str = event.get('date', '')
                description = event.get('description', 'Unknown')
                event_type = event.get('type', 'event')
                
                try:
                    # Try to parse date
                    if 'T' in date_str:
                        date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    else:
                        date = datetime.strptime(date_str[:10], '%Y-%m-%d')
                    
                    events.append({
                        'date': date,
                        'description': description,
                        'type': event_type
                    })
                except:
                    pass
        
        if not events:
            print("[!] No valid date events")
            return None
        
        # Sort by date
        events.sort(key=lambda x: x['date'])
        
        # Create timeline
        dates = [e['date'] for e in events]
        descriptions = [e['description'] for e in events]
        
        # Create scatter plot
        y_positions = list(range(len(events)))
        
        plt.scatter(dates, y_positions, s=100, c='red', edgecolors='black', zorder=3)
        
        # Add event labels
        for i, (date, desc, y) in enumerate(zip(dates, descriptions, y_positions)):
            plt.text(date, y + 0.1, desc, fontsize=9, 
                    bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.8))
        
        # Add connecting line
        plt.plot(dates, y_positions, 'gray', alpha=0.5, linewidth=1)
        
        plt.title('Event Timeline', fontsize=16, fontweight='bold')
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Event', fontsize=12)
        plt.yticks([])
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        if save:
            filename = f"{self.output_dir}/event_timeline.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"[✓] Saved: {filename}")
            plt.close()
            return filename
        else:
            plt.show()
            return None
    
    def generate_dashboard(self, extracted_data):
        """Generate comprehensive dashboard of all visualizations"""
        print("[+] Generating data visualization dashboard...")
        
        dashboard_files = []
        
        # 1. Student distribution
        if 'students' in extracted_data or 'student_data' in extracted_data:
            student_data = extracted_data.get('students', extracted_data.get('student_data', []))
            if student_data:
                dist_file = self.plot_student_distribution(student_data)
                if dist_file:
                    dashboard_files.append(('Student Distribution', dist_file))
        
        # 2. Grade chart
        if 'grades' in extracted_data or 'student_data' in extracted_data:
            grade_data = extracted_data.get('grades', extracted_data.get('student_data', []))
            if grade_data:
                grade_file = self.create_grade_chart(grade_data)
                if grade_file:
                    dashboard_files.append(('Grade Distribution', grade_file))
        
        # 3. Network graph
        if 'relationships' in extracted_data:
            rel_data = extracted_data.get('relationships', [])
            if rel_data:
                network_file = self.generate_network_graph(rel_data)
                if network_file:
                    dashboard_files.append(('Network Graph', network_file))
        
        # 4. Timeline
        if 'timeline' in extracted_data:
            timeline_data = extracted_data.get('timeline', [])
            if timeline_data:
                timeline_file = self.create_timeline_chart(timeline_data)
                if timeline_file:
                    dashboard_files.append(('Event Timeline', timeline_file))
        
        # Generate HTML dashboard
        self.generate_html_dashboard(dashboard_files)
        
        return dashboard_files
    
    def generate_html_dashboard(self, visualization_files):
        """Generate HTML dashboard page"""
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>School Data Visualization Dashboard</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 20px;
                    padding: 30px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                }
                .header {
                    text-align: center;
                    margin-bottom: 40px;
                    padding-bottom: 20px;
                    border-bottom: 3px solid #667eea;
                }
                .header h1 {
                    color: #333;
                    margin: 0;
                    font-size: 2.5em;
                }
                .header p {
                    color: #666;
                    font-size: 1.1em;
                }
                .visualizations {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
                    gap: 30px;
                }
                .viz-card {
                    background: white;
                    border-radius: 15px;
                    padding: 20px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    transition: transform 0.3s;
                }
                .viz-card:hover {
                    transform: translateY(-5px);
                }
                .viz-card h3 {
                    color: #667eea;
                    margin-top: 0;
                    border-bottom: 2px solid #f0f0f0;
                    padding-bottom: 10px;
                }
                .viz-card img {
                    width: 100%;
                    height: auto;
                    border-radius: 10px;
                    border: 1px solid #eee;
                }
                .timestamp {
                    text-align: center;
                    margin-top: 30px;
                    color: #888;
                    font-size: 0.9em;
                }
                .stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .stat-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                }
                .stat-card h3 {
                    margin: 0;
                    font-size: 2em;
                }
                .stat-card p {
                    margin: 5px 0 0;
                    opacity: 0.9;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 School Data Visualization Dashboard</h1>
                    <p>Generated from extracted school database information</p>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <h3>""" + str(len(visualization_files)) + """</h3>
                        <p>Visualizations</p>
                    </div>
                    <div class="stat-card">
                        <h3>""" + datetime.now().strftime("%Y-%m-%d") + """</h3>
                        <p>Generated Date</p>
                    </div>
                </div>
                
                <div class="visualizations">
        """
        
        # Add each visualization
        for title, filepath in visualization_files:
            filename = os.path.basename(filepath)
            html_content += f"""
                    <div class="viz-card">
                        <h3>{title}</h3>
                        <img src="{filename}" alt="{title}">
                        <p><small>File: {filename}</small></p>
                    </div>
            """
        
        # Close HTML
        html_content += f"""
                </div>
                
                <div class="timestamp">
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by EduDB Extractor Toolkit</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save HTML file
        html_file = f"{self.output_dir}/dashboard.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[✓] Dashboard saved: {html_file}")
        
        # Copy visualization images to dashboard directory
        import shutil
        for _, filepath in visualization_files:
            if os.path.exists(filepath):
                shutil.copy2(filepath, self.output_dir)
        
        return html_file

# Example usage
if __name__ == "__main__":
    # Sample data for testing
    sample_students = [
        {'nama': 'Andi', 'kelas': 'X IPA 1', 'nilai': 85},
        {'nama': 'Budi', 'kelas': 'X IPA 1', 'nilai': 78},
        {'nama': 'Citra', 'kelas': 'X IPA 2', 'nilai': 92},
        {'nama': 'Dewi', 'kelas': 'X IPA 2', 'nilai': 88},
        {'nama': 'Eka', 'kelas': 'XI IPS 1', 'nilai': 76},
    ]
    
    visualizer = DataVisualizer()
    
    # Test visualizations
    print("[+] Testing data visualizations...")
    
    # 1. Student distribution
    dist_file = visualizer.plot_student_distribution(sample_students)
    
    # 2. Grade chart
    grade_file = visualizer.create_grade_chart(sample_students)
    
    # 3. Generate dashboard
    extracted_data = {
        'students': sample_students,
        'grades': sample_students,
        'relationships': [
            {'source': 'Teacher', 'target': 'Andi', 'weight': 1},
            {'source': 'Teacher', 'target': 'Budi', 'weight': 1},
        ],
        'timeline': [
            {'date': '2024-01-15', 'description': 'Midterm Exams'},
            {'date': '2024-03-20', 'description': 'Parent-Teacher Meeting'},
        ]
    }
    
    dashboard = visualizer.generate_dashboard(extracted_data)
    print(f"[✓] Generated {len(dashboard)} visualizations")
