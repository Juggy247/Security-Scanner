from typing import List, Dict, Any, Optional
from datetime import datetime
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
import logging

logger = logging.getLogger(__name__)

#configuration system

class MongoDbConfig:

    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        try:
            self.client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')

            self.db = self.client['security_scanner']   #testing connection 

            self.suspicious_tlds = self.db['suspicious_tlds']
            self.brands = self.db['brands']
            self.blacklisted_domains = self.db['blacklisted_domains']
            self.suspicious_keywords = self.db['suspicious_keywords']
            self.config_history = self.db['config_history']

            self._create_indexes()  
            
            logger.info("MongoDb is successfully running!\n")

        except ConnectionFailure as e:
            logger.error(f"Connection Failed: {e}\n")
            raise

    
    def _create_indexes(self):

        #unique index for fast search
        self.suspicious_tlds.create_index('tld', unique=True)
        self.brands.create_index('brand_name', unique=True)
        self.blacklisted_domains.create_index('domain', unique=True)

        #with ascending and desending method for fast query
        self.suspicious_tlds.create_index([('is_active', ASCENDING)])
        self.brands.create_index([('is_active', ASCENDING)])
        self.blacklisted_domains.create_index([
            ('is_active', ASCENDING),
            ('added_date', DESCENDING)
        ])

    def get_suspicious_tlds(self, include_inactive: bool = False ):

        if include_inactive:
            query = {}
        else:
            query = {'is_active': True}

        tlds = self.suspicious_tlds.find(query)

        tld_list = []
        for tld in tlds:
            tld_list.append(tld['tld'])

        return tld_list

    def get_tld_details(self, tld: str) -> Optional[Dict[str, Any]]:

        return self.suspicious_tlds.find_one({'tld': tld})

    def add_suspicious_tld(self, tld: str,risk_level: str = 'medium', reason: str='',
                        added_by: str = 'system'):
        try: 
            docs = {
                'tld': tld.lower().replace('.', ''),
                    'risk_level': risk_level,
                    'reason': reason,
                    'added_date': datetime.now(),
                    'added_by': added_by,
                    'is_active': True,
                    'last_updated': datetime.now()
            }

            self.suspicious_tlds.insert_one(docs)
            #self._log_change('add_tld', docs, added_by)

            logger.info(f"New tlds is added to the system: {tld}")
            return True
        
        except DuplicateKeyError:
            logger.warning(f"{tld} is already exist in the system")
            return False
        

    def update_tld(self, tld: str, **updates):      #**update - collect extra args into a dictionary

        updates['last_updated'] = datetime.now()

        result = self.suspicious_tlds.update_one(
            {'tld': tld},
            {'$set': updates}
        )

        if result.modified_count > 0:
            #self._log_change('update_tld', {'tld': tld, **updates}, 'admin')
            return True
        
        return False 

    def deactivate_tld(self, tld: str):
        return self.update_tld(tld, is_active=False)


    def get_brands(self, category=None):
        query = {'is_active': True}
        if category:
            query['category'] = category

        brands = self.brands.find(query)

        result = []

        for brand in brands:
            result.append(brand['brand_name'])
        return result


    def add_brand(self, brand_name: str, category: str = 'general',
                priority: str = 'medium',
                added_by: str = 'system'):
        
        try:
            doc = {
                'brand_name': brand_name.lower(),
                'category': category,
                'added_date': datetime.now(),
                'added_by': added_by,
                'is_active': True,
                'last_updated': datetime.now()
                }
                
            self.brands.insert_one(doc)
            #self._log_change('add_brand', doc, added_by)
                
            logger.info(f"Added brand: {brand_name}")
            return True
        
        except DuplicateKeyError:
            logger.warning(f"Brand: {brand_name} is already exist")
            return False
        

    def get_brand_categories(self):
            return self.brands.distinct('category')

        
    def is_blacklisted(self, domain: str):
        result = self.blacklisted_domains.find_one({
            'domain': domain.lower(),
            'is_active': True
        })  # we get full json documents return inside result if there is a match

        return result is not None

    def add_blacklisted_domain(self, domain: str, source: str='manual',reason: str='', added_by: str= 'system'):

        try:
            doc = {
                'domain': domain.lower(),
                'source': source,
                'reason': reason,
                'added_date': datetime.now(),
                'added_by': added_by,
                'is_active': True,
            }

            self.blacklisted_domains.insert_one(doc)
            #self._log_change('blacklist_domain', doc, added_by)
            
            logger.info(f" Blacklisted: {domain}")
            return True
                
        except DuplicateKeyError:
            
            logger.warning(f" Domain '{domain}' is already blacklisted")
            return False

    def get_blacklisted_domains(self, limit: int = 1000):

        domains = self.blacklisted_domains.find({'is_active': True}).limit(limit)

        domain_list = []
        for d in domains:
            domain_list.append(d['domain'])
        return domain_list

    def search_blacklist(self, query: str):
        results = self.blacklisted_domains.find({
                'domain': {'$regex': query, '$options': 'i'},   #option (i) mean make regex case insensitive
                'is_active': True
            })
        return list(results)

    def get_suspicious_keywords(self, category= None):
        
            query = {'is_active': True}
            if category:
                query['category'] = category
            
            keywords = self.suspicious_keywords.find(query)
            keywords_list = []
            for kw in keywords:
                keywords_list.append(kw['keyword'])

            return keywords_list

    def add_suspicious_keyword(self, keyword: str, category: str = 'action_words', risk_level: str = 'medium'):   
        try:
            doc = {
                    'keyword': keyword.lower(),
                    'category': category,
                    'risk_level': risk_level,
                    'added_date': datetime.now(),
                    'is_active': True
                }
                    
            self.suspicious_keywords.insert_one(doc)
            return True
                    
        except DuplicateKeyError:
            return False

    def delete_tld(self, tld: str) -> bool:
        result = self.suspicious_tlds.delete_one({'tld': tld})
        return result.deleted_count > 0

    def delete_brand(self, brand_name: str) -> bool:
        result = self.brands.delete_one({'brand_name': brand_name.lower()})
        return result.deleted_count > 0

    def delete_blacklisted_domain(self, domain: str) -> bool:
        result = self.blacklisted_domains.delete_one({'domain': domain.lower()})
        return result.deleted_count > 0

    def delete_suspicious_keyword(self, keyword: str) -> bool:
        result = self.suspicious_keywords.delete_one({'keyword': keyword.lower()})
        return result.deleted_count > 0
    

    #Connection closed
    def close(self):
            
        self.client.close()
          








        #helper functions for importing data into mongodb

    def add_multiple_tlds(self, tlds: List[Dict]) -> int:
           
            added = 0
            for tld_data in tlds:
                if self.add_suspicious_tld(**tld_data):
                    added += 1
            return added

    def add_multiple_brands(self, brands: List[Dict]) -> int:
            
            added = 0
            for brand_data in brands:
                if self.add_brand(**brand_data):
                    added += 1
            return added

    def add_multiple_keywords(self, keywords: List[Dict]) -> int:
           
            added = 0
            for kw_data in keywords:
                if self.add_suspicious_keyword(**kw_data):
                    added += 1
            return added
