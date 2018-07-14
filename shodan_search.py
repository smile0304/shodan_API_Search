import optparse
import sys
import os
import shodan
import json
import collections
from config import API_KEY
from search import Shodan_sort


def initconnect():
    """
    init SHODAN_API_KEY
    :return: api
    """
    api = Shodan_sort(API_KEY)
    return api


def keyword_search(api, keyword, limit):
    """
    :param api: Use initconnect method generated api
    :param keyword: Want query keyword
    :param limit: Want query numbers
    :return: results
    """
    vulner_number = []
    results = collections.OrderedDict(api.search(keyword,limit=limit))
    return results


def input_result(keyword, results,lib=None):
    #print(json.dumps(results['matches'][0], indent=4))
    if lib is None:
        filename = "search_result.txt"
    else:
        filename = lib+"/search_result.txt"
    try:
        fileobj = open(filename,'w',encoding="utf-8")
        fileobj.write("数据条数:{}\n".format(results["total"]))
        for result in results["matches"]:
            fileobj.write(str(result)+"\n")
    except Exception as e:
        print("文件读取错误"+ e)
    finally:
        fileobj.close()
    print("文件{}写入完成".format(filename))


def get_Vulner(api,keyword,lib=None):
    vulners = api.exploits.search(keyword)
    if vulners["total"] == 0:
        print("没有检索到exp")
    else:
        try:
            if lib is None:
                filename = "cve_exp"+'.txt'
            else:
                filename = lib+"/cve_exp"+'.txt'
            fileobj = open(filename,'w',encoding="utf-8")
            fileobj.write("检索到漏洞和exp的总条数:{}\n".format(vulners["total"]))
            for vulner in vulners["matches"]:
                fileobj.write(str(vulner)+"\n")
        except Exception as e:
            print("文件读取错误:"+e)
        finally:
            fileobj.close()
            print("文件{}写入完成".format(filename))


def get_file(api,filename):
    fileobj = open(filename)
    while True:
        line = fileobj.readline()
        if not line:
            break
        all = line.split(":::")
        lib = all[0]
        os.mkdir(lib)
        results = keyword_search(api,all[1],all[2])
        input_result(all[1],results,lib=lib)
        get_Vulner(api,all[1],lib=lib)
    fileobj.close()


if __name__ == "__main__":
    parser = optparse.OptionParser("usage:%prog wait")
    parser.add_option("-k", "--keyword",type='string',dest='keyword',help="Please input you want search keyword")
    parser.add_option("-l", "--limit",type="int",dest="limit",default=100)
    parser.add_option("-f", "--file",type="string",dest="file",help="Specified file")

    (options,args) = parser.parse_args()
    api = initconnect()
    if options.keyword is None and options.file is None:
        parser.print_help()
        print("Keyword and file Cannot be None at the same time")
        sys.exit(0)
    elif options.file is None and options.keyword is not None:
        keyword = options.keyword
        limit = options.limit
        results = keyword_search(api,keyword,limit)
        input_result(keyword,results)
        get_Vulner(api,keyword)
    elif options.file is not None and options.keyword is None:
        filename = options.file
        get_file(api,filename)