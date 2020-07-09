import re as regex
import csv
from lan_project.models import NvdData

# Some helper functions for lan_project application


# Takes an input cve as a string from database, refactors it to be more readable and returns it!
def list_refactor_services(list_item):
    list_item = [w.replace('(', '') for w in list_item]
    list_item = [w.replace(')', '') for w in list_item]
    list_item = [w.replace('\'', '') for w in list_item]
    list_item = [w.replace('[', '') for w in list_item]
    list_item = [w.replace(']', '') for w in list_item]
    # print('List_refactor function executed')
    return list_item


def string_replacer(str_input):
    str_input = str_input.replace('(', '')
    str_input = str_input.replace(')', '')
    str_input = str_input.replace('\r', '')
    str_input = str_input.replace('\n', '')
    # print('String_replacer function executed')
    return str_input


def reform_banner(banner):
    for service in banner.split('\n'):
        # Server: Mini web server 1.0 ZTE corp 2005.
        # Server: 202 (vsFTPd 3.0.3)
        if 'Server:' in service:
            service = service[8:]
            return service


# Class for service analysis
# If service isn't apache it just returns the service as the result.
class ServiceManager:
    # function for services running in ports != 80
    # some example services that will be passed in the function
    # vsFTPd 3.0.3
    @staticmethod
    def analyze_service(inp_service):
        # remove starting and ending spaces
        inp_service = inp_service.strip()
        print('Analyze service function for service : {} started.'.format(inp_service))
        # APACHE SERVICES... can be ( Apache/2.4++ or Apache or Apache httpd 2.2.2)
        if 'Apache' and '/' in inp_service:
            inp_service = inp_service.split('/')
            apache_query = '%Apache http%'
            # inp_service now is inp_service[0]= 'Apache', inp_service[1]= '2.4.41'
            print('[+] Apache service with version found! --> {}'.format(inp_service))
            # check if version has 2. in it we search for apache http and 2020 as date.
            apache_results = [inp_service[0], inp_service[1]]
            if '2.' in inp_service[1]:
                date_query = '%2020%'
                return apache_results, apache_query, date_query
            else:
                # TODO: If no version is found maybe provide the latest exploits ??
                date_query = '%2019%'
                return apache_results, apache_query, date_query
        else:
            # for example vsFTPd 3.0.3
            if ' ' in inp_service:
                space_char = ' '
                pos = []
                for i in range(0, len(inp_service)):
                    if inp_service[i] == space_char:
                        pos.append(i)
                print('starting string was:', inp_service)
                print('We keep:', inp_service[:pos[-2]])
                reformed_service_with_spaces = inp_service[:pos[-2]]
                serv_name = ''.join(('%', reformed_service_with_spaces, '%'))
                serv_date = '%2019%'
                print(serv_name)
                return reformed_service_with_spaces, serv_name, serv_date
            else:
                # nginx service or Swift1.0
                # checking if the service has its version without space.
                serv_name = 'Null'
                serv_date = '2020'
                reformed_service_with_spaces = 'Swift'
            #  if regex.match()
                return reformed_service_with_spaces, serv_name, serv_date

    @staticmethod
    # Identifies version and returns the correct date to search in the database.
    def analyze_date(version_list_item):
        # check if version is 2. or higher
        print('figure date function executed')
        if '2.' in version_list_item:
            print('Version>2 ....Will query dates %2020%')
            date_query = '%2020%'
        else:
            print('Version != 2 ....Will query dates %2019%')
            date_query = '%2019%'
        return date_query


def update_nvd_model():
    CSV_PATH = '/home/ianmoone/Development/ThesisEnv/src/allitems.csv'
    count_success = 0
    # Remove all data from table
    NvdData.objects.all().delete()
    with open(CSV_PATH, encoding='utf-8', errors='ignore', newline='') as csvfile:
        sreader = csv.reader(csvfile, delimiter=',', quotechar=';')
        print('Parsing data and creating the model..(this could take some time)')
        for row in sreader:
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            next(sreader, None)
            NvdData.objects.get_or_create(cve=row[0], status=row[1], description=row[2], references=row[3],
                                          phase=row[4], votes=row[5])
            count_success += 1
        print('Number of rows inserted :', count_success)
