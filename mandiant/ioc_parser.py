from lxml import etree
from random import choice
import datetime
import time
import csv


# generates a random id
def generate_id():
    alfabet=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    id=''
    for i in range(8):
        id+=choice(alfabet)
    id+='-'
    for i in range(4):
        id+=choice(alfabet)
    id+='-'
    for i in range(4):
        id+=choice(alfabet)
    id+='-'    
    for i in range(4):
        id+=choice(alfabet)
    id+='-'
    for i in range(12):
        id+=choice(alfabet)
    return id

# reads intelligence items from a csv, assuming that each line represents a different set of IOCs
def read_from_csv(filename):
    intel=[]
    with open(filename,'rb') as csvfile:
        headers=[]
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in spamreader:            
            if (len(headers) == 0):
                headers = row
                vet_intelligence(headers)
            else:
                elements={}
                for i, element in enumerate(row):
                    elements[headers[i]]=element
                intel.append(elements)
    return intel
            
# vets the intelligence and tries to sort it based on the ioc terms            
def vet_intelligence(intel):
    global metadata
    potential_terms=load_intel_framework()
    for intl in intel:
        found=False
        for poterm in potential_terms:
            if intl == poterm['title']:
                found=True
                metadata.append(poterm)
                break
        if not found:
            raise NameError("intelligence term cannot be found in the repository")
            
        

# loading the intel framework from the iocterms 
def load_intel_framework():
    intel=load_intel_terms('Common.iocterms')
    intel+=load_intel_terms('IOCFinder.iocterms')
    intel+=load_intel_terms('Current.iocterms')
    return intel

#load the intel terms from the *.ioc file sent as the [filename] parameter    
def load_intel_terms(filename):
    terms_tree=etree.parse(open(filename,'r'))
    term_arr=[]
    for term in terms_tree.iter("{http://schemas.mandiant.com/2010/ioc}iocterm"):
        tar={}
        for attr,value in term.items():
            tar[attr]=value
        term_arr.append(tar)
    return term_arr


# return the iocterm metadata stored for this type of inteligence
def get_metadata(term):
    for trm in metadata:
        if term == trm["title"]:
            return trm

def create_indicator_item(details,parent):
#    print details
    for key in details.keys():
        value = details[key]
        if value != '':
            ii=etree.SubElement(parent,"IndicatorItem")
            ii.set('id',generate_id())
            ii.set('condition',"contains")
            context=etree.SubElement(ii,"Context")
            trm=get_metadata(key)
            context.set("document",trm["text"].split("/")[0])
            context.set("search",trm["text"])
            context.set("type",'mir')
            content=etree.SubElement(ii,"Content")
            content.set('type',trm['display-type'])
            content.text=value
        
# creates the mandiant IOC file from the set of intelligence we have. Will first look at all the possible fields in the iocterms files and then will create the file
def create_mandiant(data,filename):
    now = datetime.datetime.now()
    tree=etree.parse(open('test_ioc.xml','r'))
    root=tree.getroot()
    root.set("id",generate_id())
    root.set("lastmodified",now.strftime("%Y-%m-%dT%H:%M:%S"))
    short_description="Indicators of Compromise derived from reading a file"
    author="Subject Name Here"
    authored_date=now.strftime("%Y-%m-%dT%H:%M:%S")
    links=""
    etree.SubElement(root,"short_description").text=short_description
    etree.SubElement(root,"authored_by").text = author
    etree.SubElement(root,"authored_date").text = authored_date
    etree.SubElement(root,"links").text = links
    definitions=etree.SubElement(root,"definition")
    in_or=etree.SubElement(definitions,"Indicator")
    in_or.set('operator',"OR")
    in_or.set('id',generate_id())
    # creating elements - starting with a really basic OR between the and putting ANDs between the indicators of the same incident
    for ioc in data:
        parent_and=etree.SubElement(in_or,"Indicator")
        parent_and.set('operator',"AND")
        parent_and.set('id',generate_id())
        create_indicator_item(ioc,parent_and)
    f=open(filename,'w')
    f.write(etree.tostring(tree, method='xml', pretty_print=True))
    

metadata = []
info=read_from_csv('c2.csv')
create_mandiant(info,'dev_c2.ioc')
