
import sys
import json
from typing import Dict, List, Any
from pathlib import Path
from tabulate import tabulate
from config import MongoDbConfig

class AdminCLI:
    
    def __init__(self):
        try:
            self.db = MongoDbConfig()
            print("Connected to MongoDB successfully\n")
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            sys.exit(1)
    
    def close(self):
        
        self.db.close()
    
   
    
    def add_tld(self, tld: str, risk: str = 'medium', reason: str = '', added_by: str = 'admin'):
        
        success = self.db.add_suspicious_tld(
            tld=tld,
            risk_level=risk,
            reason=reason,
            added_by=added_by
        )
        
        if success:
            print(f"Successfully added TLD: .{tld} (risk: {risk})")
        else:
            print(f"TLD .{tld} already exists in the database")
    
    def list_tlds(self, include_inactive: bool = False, output_json: bool = False):
        
        query = {} if include_inactive else {'is_active': True}
        tlds = self.db.suspicious_tlds.find(query)
        
        tld_list = []
        for tld in tlds:
            tld_list.append({
                'TLD': f".{tld['tld']}",
                'Risk Level': tld.get('risk_level', 'N/A'),
                'Reason': tld.get('reason', 'N/A')[:50],  
                'Active': '✓' if tld.get('is_active', True) else '✗',
                'Added By': tld.get('added_by', 'N/A')
            })
        
        if output_json:
            print(json.dumps(tld_list, indent=2))
        else:
            if tld_list:
                print(tabulate(tld_list, headers='keys', tablefmt='grid'))
                print(f"\n📊 Total TLDs: {len(tld_list)}")
            else:
                print("📭 No TLDs found in database")
    
    def update_tld(self, tld: str, risk: str = None, reason: str = None):
        
        updates = {}
        if risk:
            updates['risk_level'] = risk
        if reason:
            updates['reason'] = reason
        
        if not updates:
            print("No updates specified. Use --risk or --reason")
            return
        
        success = self.db.update_tld(tld, **updates)
        if success:
            print(f"Successfully updated TLD: .{tld}")
        else:
            print(f"TLD .{tld} not found or no changes made")
    
    def remove_tld(self, tld: str, force: bool = False):
        
        if not force:
            confirm = input(f"Delete TLD '.{tld}'? This action cannot be undone. (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled")
                return
        
        success = self.db.delete_tld(tld)
        if success:
            print(f"Successfully deleted TLD: .{tld}")
        else:
            print(f"TLD .{tld} not found")
    
    def deactivate_tld(self, tld: str):
       
        success = self.db.deactivate_tld(tld)
        if success:
            print(f"Successfully deactivated TLD: .{tld}")
        else:
            print(f"TLD .{tld} not found")

    
    
    def add_brand(self, name: str, category: str = 'general', added_by: str = 'admin'):
        
        success = self.db.add_brand(
            brand_name=name,
            category=category,
            added_by=added_by
        )
        
        if success:
            print(f"Successfully added brand: {name} (category: {category})")
        else:
            print(f"Brand '{name}' already exists in the database")
    
    def list_brands(self, category: str = None, output_json: bool = False):
        
        query = {'is_active': True}
        if category:
            query['category'] = category
        
        brands = self.db.brands.find(query)
        
        brand_list = []
        for brand in brands:
            brand_list.append({
                'Brand': brand['brand_name'],
                'Category': brand.get('category', 'N/A'),
                'Added By': brand.get('added_by', 'N/A')
            })
        
        if output_json:
            print(json.dumps(brand_list, indent=2))
        else:
            if brand_list:
                print(tabulate(brand_list, headers='keys', tablefmt='grid'))
                print(f"\nTotal Brands: {len(brand_list)}")
            else:
                print("No brands found in database")
    
    def remove_brand(self, name: str, force: bool = False):
       
        if not force:
            confirm = input(f"Delete brand '{name}'? This action cannot be undone. (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled")
                return
        
        success = self.db.delete_brand(name)
        if success:
            print(f"Successfully deleted brand: {name}")
        else:
            print(f"Brand '{name}' not found")
    
    
    
    def add_blacklist(self, domain: str, source: str = 'manual', reason: str = '', added_by: str = 'admin'):
        
        success = self.db.add_blacklisted_domain(
            domain=domain,
            source=source,
            reason=reason,
            added_by=added_by
        )
        
        if success:
            print(f"Successfully blacklisted domain: {domain}")
        else:
            print(f"Domain '{domain}' is already blacklisted")
    
    def list_blacklist(self, limit: int = 100, output_json: bool = False):
        
        domains = self.db.blacklisted_domains.find({'is_active': True}).limit(limit)
        
        domain_list = []
        for domain in domains:
            domain_list.append({
                'Domain': domain['domain'],
                'Source': domain.get('source', 'N/A'),
                'Reason': domain.get('reason', 'N/A')[:50],
                'Added By': domain.get('added_by', 'N/A')
            })
        
        if output_json:
            print(json.dumps(domain_list, indent=2))
        else:
            if domain_list:
                print(tabulate(domain_list, headers='keys', tablefmt='grid'))
                print(f"\nShowing {len(domain_list)} blacklisted domains")
            else:
                print("No blacklisted domains found")
    
    def search_blacklist(self, query: str, output_json: bool = False):
        
        results = self.db.search_blacklist(query)
        
        domain_list = []
        for domain in results:
            domain_list.append({
                'Domain': domain['domain'],
                'Source': domain.get('source', 'N/A'),
                'Reason': domain.get('reason', 'N/A')[:50]
            })
        
        if output_json:
            print(json.dumps(domain_list, indent=2))
        else:
            if domain_list:
                print(tabulate(domain_list, headers='keys', tablefmt='grid'))
                print(f"\nFound {len(domain_list)} matching domains")
            else:
                print(f"No domains found matching '{query}'")
    
    def remove_blacklist(self, domain: str, force: bool = False):
       
        if not force:
            confirm = input(f"Remove '{domain}' from blacklist? This action cannot be undone. (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled")
                return
        
        success = self.db.delete_blacklisted_domain(domain)
        if success:
            print(f"Successfully removed domain from blacklist: {domain}")
        else:
            print(f"Domain '{domain}' not found in blacklist")
    
    
    
    def add_keyword(self, keyword: str, category: str = 'action_words', risk: str = 'medium'):
        
        success = self.db.add_suspicious_keyword(
            keyword=keyword,
            category=category,
            risk_level=risk
        )
        
        if success:
            print(f"Successfully added keyword: {keyword} (category: {category})")
        else:
            print(f"Keyword '{keyword}' already exists")
    
    def list_keywords(self, category: str = None, output_json: bool = False):
        
        query = {'is_active': True}
        if category:
            query['category'] = category
        
        keywords = self.db.suspicious_keywords.find(query)
        
        keyword_list = []
        for kw in keywords:
            keyword_list.append({
                'Keyword': kw['keyword'],
                'Category': kw.get('category', 'N/A'),
                'Risk Level': kw.get('risk_level', 'N/A')
            })
        
        if output_json:
            print(json.dumps(keyword_list, indent=2))
        else:
            if keyword_list:
                print(tabulate(keyword_list, headers='keys', tablefmt='grid'))
                print(f"\nTotal Keywords: {len(keyword_list)}")
            else:
                print(" No keywords found")
    
    def remove_keyword(self, keyword: str, force: bool = False):
        
        if not force:
            confirm = input(f"Delete keyword '{keyword}'? This action cannot be undone. (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled")
                return
        
        success = self.db.delete_suspicious_keyword(keyword)
        if success:
            print(f"Successfully deleted keyword: {keyword}")
        else:
            print(f"Keyword '{keyword}' not found")
    
   
    
    def show_stats(self):
        
        
        total_tlds = self.db.suspicious_tlds.count_documents({'is_active': True})
        total_brands = self.db.brands.count_documents({'is_active': True})
        total_blacklist = self.db.blacklisted_domains.count_documents({'is_active': True})
        total_keywords = self.db.suspicious_keywords.count_documents({'is_active': True})
        
        
        tld_risk_counts = {}
        for risk in ['low', 'medium', 'high', 'critical']:
            count = self.db.suspicious_tlds.count_documents({'is_active': True, 'risk_level': risk})
            tld_risk_counts[risk] = count
        
        
        keyword_risk_counts = {}
        for risk in ['low', 'medium', 'high']:
            count = self.db.suspicious_keywords.count_documents({'is_active': True, 'risk_level': risk})
            keyword_risk_counts[risk] = count
        
        print("=" * 60)
        print("DATABASE STATISTICS")
        print("=" * 60)
        
        
        stats_table = [
            ['Suspicious TLDs', total_tlds],
            ['Protected Brands', total_brands],
            ['Blacklisted Domains', total_blacklist],
            ['Suspicious Keywords', total_keywords]
        ]
        print("\nCollection Counts:")
        print(tabulate(stats_table, headers=['Collection', 'Count'], tablefmt='grid'))
        
        print("\nTLD Risk Level Breakdown:")
        tld_risk_table = [[level.capitalize(), count] for level, count in tld_risk_counts.items()]
        print(tabulate(tld_risk_table, headers=['Risk Level', 'Count'], tablefmt='grid'))
        
        
        print("\nKeyword Risk Level Breakdown:")
        keyword_risk_table = [[level.capitalize(), count] for level, count in keyword_risk_counts.items()]
        print(tabulate(keyword_risk_table, headers=['Risk Level', 'Count'], tablefmt='grid'))
        
        print("\n" + "=" * 60)
    
    def import_data(self, filepath: str):
        
        path = Path(filepath)
        
        if not path.exists():
            print(f"File not found: {filepath}")
            return
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            
            if 'tlds' in data:
                added = self.db.add_multiple_tlds(data['tlds'])
                print(f"Imported {added} TLDs")
            
            
            if 'brands' in data:
                added = self.db.add_multiple_brands(data['brands'])
                print(f"Imported {added} brands")
            
           
            if 'keywords' in data:
                added = self.db.add_multiple_keywords(data['keywords'])
                print(f"Imported {added} keywords")
            
            
            if 'blacklist' in data:
                added = 0
                for domain_data in data['blacklist']:
                    if self.db.add_blacklisted_domain(**domain_data):
                        added += 1
                print(f"Imported {added} blacklisted domains")
            
            print(f"\nImport completed from {filepath}")
            
        except json.JSONDecodeError as e:
            print(f"Invalid JSON format: {e}")
        except Exception as e:
            print(f"Import failed: {e}")
    
    def export_data(self, filepath: str):
        
        try:
            
            data = {
                'tlds': [],
                'brands': [],
                'keywords': [],
                'blacklist': []
            }
            
            
            for tld in self.db.suspicious_tlds.find({'is_active': True}):
                data['tlds'].append({
                    'tld': tld['tld'],
                    'risk_level': tld.get('risk_level', 'medium'),
                    'reason': tld.get('reason', ''),
                    'added_by': tld.get('added_by', 'system')
                })
            
            
            for brand in self.db.brands.find({'is_active': True}):
                data['brands'].append({
                    'brand_name': brand['brand_name'],
                    'category': brand.get('category', 'general'),
                    'added_by': brand.get('added_by', 'system')
                })
            
            
            for kw in self.db.suspicious_keywords.find({'is_active': True}):
                data['keywords'].append({
                    'keyword': kw['keyword'],
                    'category': kw.get('category', 'action_words'),
                    'risk_level': kw.get('risk_level', 'medium')
                })
            
            
            for domain in self.db.blacklisted_domains.find({'is_active': True}):
                data['blacklist'].append({
                    'domain': domain['domain'],
                    'source': domain.get('source', 'manual'),
                    'reason': domain.get('reason', ''),
                    'added_by': domain.get('added_by', 'system')
                })
            
           
            path = Path(filepath)
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"Data exported to {filepath}")
            print(f"   - {len(data['tlds'])} TLDs")
            print(f"   - {len(data['brands'])} brands")
            print(f"   - {len(data['keywords'])} keywords")
            print(f"   - {len(data['blacklist'])} blacklisted domains")
            
        except Exception as e:
            print(f"Export failed: {e}")