import csv,os, argparse
from bs4 import BeautifulSoup

def htmlLogScraper(htmlReport):
    outputLogName = (htmlReport.split('\\')[1].split('.html')[0])
    output = open(f'./logs/{outputLogName}.csv','w',newline='')
    csv_output = csv.writer(output)
    csv_output.writerow(['URI','Status','Response Time','Context','File Origin','Resource Type','Property Name','Value','Expected','Actual','Result'])
    htmlLog = open(htmlReport,'r')
    soup = BeautifulSoup(htmlLog, 'html.parser')
    glanceDetails = {}
    idList = []
    table = soup.find_all('table', {'class':'titletable'})
    for tbl in table:
        tr = tbl.find('tr')
        URIresp = tr.find('td',{'class':'title'}) # URI, response time, show results button
        URI = URIresp.text.partition('(')[0]
        responseTime = URIresp.text.partition('response time')[2].split(')')[0].strip(':s')
        StatusGET = tr.find('td',{'class':'pass'}) or tr.find('td',{'class':'fail'})
        if 'Success' in StatusGET.text:
            Status = '200'
        else:
            Status = '400'

        context,FileOrigin,ResourceType = ' ',' ',' '
        if 'Context:' in tr.find_all('td')[1].text:
            context = tr.find_all('td')[1].text.split('Context:')[1].split('File')[0]
        if 'File Origin'in tr.find_all('td')[1].text:
            FileOrigin = tr.find_all('td')[1].text.split('File Origin:')[1].split('Resource')[0]
        if 'Resource Type'in tr.find_all('td')[1].text:
            ResourceType = tr.find_all('td')[1].text.split('Resource Type:')[1]
        resNumHtml = str(tr.find('div', {'class':'button warn'}))
        resNum = resNumHtml.split('.')[1].split('getElementById')[1].strip("()'")
        idList.append(resNum)
        results = URI+'*'+Status+'*'+responseTime+'*'+context+'*'+FileOrigin+'*'+ResourceType+'*' #using * for csv splitting since some values have commas
        glanceDetails[results] = resNum # mapping of results to their respective tables

    properties = soup.findAll('td',{'class':'results'})
    data = []
    for table in properties:
        tableToStr = str(table)
        tableID = tableToStr.split('id=')[1].split('>')[0].strip('"')
        tableBody = table.find_all('table')[1]
        tableRows = tableBody.find_all('tr')[1:] #get rows from property tables excluding header
        for tr in tableRows:
            td = tr.find_all('td')
            row = [i.text for i in td]
            for k,v in glanceDetails.items():
                if v == tableID:
                    data.append(k+'*'.join(row))
    csv_output.writerows([x.split('*') for x in data]) #using * for csv splitting since some values have commas
parser = argparse.ArgumentParser(description='Get an excel sheet of details shown in the HTML reports for the Redfish Interoperability Validator')
parser.add_argument('-html_log','--hLog' ,type=str, help = 'Path of the HTML log to be converted to csv format' )
args = parser.parse_args()

htmlLogScraper(args.hLog)