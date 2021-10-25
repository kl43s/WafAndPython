import base64
import json
import pandas
import matplotlib
from pylab import title, figure, xlabel, ylabel, xticks, bar, legend, axis, savefig
from fpdf import FPDF
import datetime
import asyncio
import subprocess

date = str(datetime.datetime.now()).split(' ')[0]

def config_file(ip_addr, authent, version):

	file = open("hebdo.sh", "a")
	start = '''curl --silent 'https://''' + ip_addr + ''':3001/api/console/proxy?path=%2F_search&method=POST' \\
  -H 'Connection: keep-alive' \\
  -H 'Authorization: Basic ''' + authent + ''' ' \\
  -H 'Accept: application/json, text/plain, */*' \\
  -H 'kbn-version: ''' + version + ''' ' \\
  -H 'content-type: application/x-ndjson' \\
  -H 'Origin: https://''' + ip_addr + ''':3001' \\
  -H 'Sec-Fetch-Site: same-origin' \\
  -H 'Sec-Fetch-Mode: cors' \\
  -H 'Sec-Fetch-Dest: empty' \\
  -H 'Referer: https://''' + ip_addr + ''':3001/app/kibana' \\
  -H 'Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7' \\
  --data-binary $'
{
    "version": true,
    "size": 1500,
    "sort": [{
        "@timestamp": {
            "order": "desc"
        }
    }],
    "query": {
        "bool": {
            "must": [{
                "exists": { "field": "events.tokens.attackFamily" }
            }, {
                "range": {
                    "events.tokens.riskLevelOWASP": {
                        "lte" : 10
                    }
                }
            }, {
                "range": {
                    "@timestamp": {
                        "gte":  "now-24h"
                    }
                }
            }]
        }
    },
    "script_fields": {
      "timestamp": {
              "script": {
                  "lang": "painless",
                  "source": "Instant.ofEpochMilli(doc[\\\\"timestamp\\\\"].value).atZone(ZoneId.of(\\'Europe/Paris\\')).format(DateTimeFormatter.ofPattern(\\'dd.MM.yyyy HH:mm:ss\\'))"
                }
            },

      "OwaspScore": {
        "script": {
          "source": "doc[\\'events.tokens.riskLevelOWASP\\']"
        }
      },

        "cible": {
          "script": {
            "source": "doc[\\'request.hostname\\']"
          }
        },

        "Attaquant": {
          "script":{
            "source": "doc[\\'request.ipSrc\\']"
          }
	  },

          "Victime": {
            "script": {
              "source": "doc[\\'request.ipDst\\']"
            }
            },

            "OwaspAttack": {
              "script": {
                "source": "doc[\\'events.tokens.attackFamily\\']"
            }
          }
        },

        "highlight": {
        "fields": {
            "*": {
                "highlight_query": {
                    "bool": {
                        "must": [{
                            "range": {
                                "@timestamp": {
                                    "gte": "now-24h"
                                }
                            }
                        }]
                    }
                }
            }
        }
    }
}' \\
  --compressed \\
  --insecure'''

	file.write(start)
	file.close()

def stats_a():

	date = str(datetime.datetime.now()).split(' ')[0]
	data = subprocess.getoutput("bash hebdo.sh")
	data = json.loads(data)
	bdd = [[], [], [], [], []] #date / ip_att / ip_cible / owasp / attackType

	file_out = open("logHistorique_" + date, "a")
	def graph(bdd):
		t = len(bdd[0])
		b = "  | "
		for i in range(t):
			file_out.write(bdd[0][i] + '\t' + bdd[1][i] + '\t' + bdd[2][i] + '\t' + str(bdd[3][i]) + '\t' + bdd[4][i] + '\n')

		file_out.close()

	try:
		taille = len(data['hits']['hits'])
		for i in range(taille):
			date = data['hits']['hits'][i]['fields']['timestamp'][0]
			ip_att = data['hits']['hits'][i]['fields']['Attaquant'][0]
			ip_cible = data['hits']['hits'][i]['fields']['cible'][0]
			owasp = data['hits']['hits'][i]['fields']['OwaspScore'][0]
			try:
				attackType = data['hits']['hits'][i]['fields']['OwaspAttack'][0]
			except KeyError:
				attackType = "null"
			bdd[0].append(date)
			bdd[1].append(ip_att)
			bdd[2].append(ip_cible)
			bdd[3].append(owasp)
			bdd[4].append(attackType)

		graph(bdd)

	except ValueError:
		False


def stats_b():

	date = str(datetime.datetime.now()).split(' ')[0]
	data = open("logHistorique_" + date, "r")
	data = data.read()

	base_data = []
	count = 0
	stats = []

	mining = ",".join(data.split('\t')).split('\n')
	T_mining = len(mining)
	for i in range(T_mining):
		if (mining[i] == ''):
			mining.pop(i)
		else:
			base_data.append(mining[i].split(','))

	for j in range(len(base_data)):
		for k in range(1, len(base_data[0])):
			count = 0
			for l in range(len(base_data)):
				if (base_data[j][k] == base_data[l][k] ):
					count += 1
			stats.append([base_data[j][k], count])

	cc = 0
	while True:
		m = 0
		n = 0
		count = 0
		while True:
			if n > len(stats) -1:
				n -= 1
			if m > len(stats) -1:
				m -= 1

			if (stats[n] == stats[m]):
				count += 1
				if count == 2:
					stats.pop(m)
					count = 0

			if (m == (len(stats) -1) ) or (m == len(stats)):
				m = 0
				if n > len(stats) -1:
					n -= 1

				if n == (len(stats) -1):
					break
				else:
					n += 1
					count = 0
			else:
				m += 1

		cc += 1
		if cc > 150:
			break
	with open("data_stats_" + date, "w") as file:
		for a in range(len(stats)):
			file.write(stats[a][0] + "\t" + str(stats[a][1]) + "\n")

def rendu():

	date = str(datetime.datetime.now()).split(' ')[0]
	file = open("data_stats_" + date, "r")
	file = file.read()
	mina = ",".join(file.split('\t')).split('\n')
	bdd = []

	for n in range(len(mina)):
		bdd.append(mina[n].split(','))

	scoreOwasp = []
	cible = []
	attaques = []
	val = ["Injection", "injection", "Traversal", "Inclusion", "(XSS)", "Path", "file", "Remote", "transversal"]
	valOwasp = ["0.0", "1.0","2.0","3.0","4.0","5.0","6.0","7.0","8.0","9.0","10.0"]

	for m in range(len(bdd)):
		if "" not in bdd[m] and ( (bdd[m][0] in valOwasp) or (bdd[m][0] in range(11)) ):
			scoreOwasp.append(bdd[m])
		for i in [".com", ".fr", ".org", ".net", ".uk", ".ru", ".local", ".blog", ".gouv"]:
			if i in (bdd[m][0]) :
				cible.append(bdd[m])
				break
		for n in val:
			if ( n in bdd[m][0]):
				if bdd[m] not in attaques:
					attaques.append(bdd[m])

	fakeAttack = 0
	realAttack = 0
	typeAttack = []
	cibleAttack = []

	for w in range(len(scoreOwasp)):
		fakeAttack += int(scoreOwasp[w][1])

	for x in range(len(attaques)):
		realAttack += int(attaques[x][1])

	for y in range(len(attaques)):
		typeAttack.append(attaques[y][0])

	for z in range(len(cible)):
		cibleAttack.append(cible[z][0])

	nbAttack = fakeAttack
	fakeAttack -= realAttack


	df = pandas.DataFrame()
	df["nbAttaque"] = [nbAttack]
	df["fakeAttaques"] = [fakeAttack]
	df["realAttaques"] = [realAttack]

	title("Comparaison des attaques")
	ylabel("Nombre d'attaque")

	bar(1, df['nbAttaque'], width=0.5, color='#C0BFBF', label='Nombre d\'attaque')
	bar(2, df['fakeAttaques'], width=0.5, color='#3386FF', label='Fausses attaques')
	bar(3, df['realAttaques'], width=0.5, color='#FF5733', label='Vrais attaques')

	legend()
	axis([0, 4, 0, nbAttack])
	savefig('figure_' + date + '.png')

	df2 = pandas.DataFrame()
	df2["typeAttaques"] = typeAttack

	df3 = pandas.DataFrame()
	df3["cibleAttaques"] = cibleAttack

	pdf = FPDF()
	pdf.add_page()
	pdf.set_xy(0, 0)
	pdf.set_font('arial', 'I', 8)
	pdf.cell(45, 10, "Rapport hebdomadaire WAF", 0, 1, 'C')
	pdf.set_font('arial', 'B', 21)
	pdf.cell(60)
	pdf.cell(90, 2, " ", 0, 2, 'C')
	pdf.cell(75, 5, 'Rapport hebdomadaire', 2, 2, 'C')
	pdf.cell(90, 5, " ", 0, 2, 'C')
	pdf.cell(75, 5, 'Données du Web Application Firewall.', 2, 2, 'C')
	pdf.cell(90, 10, " ", 0, 2, 'C')
	pdf.cell(-40)
	pdf.set_font('arial', 'B', 13)
	pdf.cell(50, 10, 'Nombre d\'attaque', 1, 0, 'C')
	pdf.cell(50, 10, 'Fausses attaques', 1, 0, 'C')
	pdf.cell(50, 10, 'Vrais attaques', 1, 2, 'C')
	pdf.cell(-100)
	pdf.set_font('arial', '', 12)
	for o in range(0, len(df)):
		pdf.cell(50, 10, '%s' % (str(df.nbAttaque.loc[o])), 1, 0, 'C')
		pdf.cell(50, 10, '%s' % (str(df.fakeAttaques.loc[o])), 1, 0, 'C')
		pdf.cell(50, 10, '%s' % (str(df.realAttaques.loc[o])), 1, 2, 'C')
		pdf.cell(-90)

	pdf.cell(90, 7, " ", 0, 2, 'C')

	pdf.set_font('arial', 'B', 13)
	pdf.cell(-10)
	pdf.cell(65, 10, 'Type d\'attaque', 1, 0, 'C')
	pdf.cell(85, 10, 'Cibles', 1, 2, 'C')
	pdf.cell(-65)
	pdf.set_font('arial', '', 12)
	p = 0
	while True:
		if p < len(df2):
			pdf.cell(65, 10, '%s' % (df2['typeAttaques'].loc[p]), 1, 0, 'C')
		else:
			pdf.cell(65, 10, " ", 0, 0, 'C')

		if p < len(df3):
			pdf.cell(85, 10, '%s' % (df3['cibleAttaques'].loc[p]), 1, 2, 'C')
		else:
			pdf.cell(85, 10, " ", 0, 2, 'C')

		pdf.cell(-65)
		if (p > len(df3)) and (p > len(df2)):
			break
		p += 1

	pdf.cell(30)
	pdf.set_font('arial', 'B', 16)
	pdf.cell(40, -10, ' ', 0, 2, 'C')
	pdf.cell(-20)
	pdf.cell(8)
	pdf.cell(20, 10, 'Détails de la semaine', 0, 2, 'C')
	pdf.set_font('arial', '', 12)
	pdf.cell(40, 1, ' ', 0, 2, 'C')
	pdf.cell(-15)
	for q in range(len(cible)):
		pdf.cell(50, 5, "L'application " + cible[q][0] + " a été ciblée " + str(cible[q][1]) + " fois depuis l'extérieur.", 0, 2, "J")
		pdf.cell(90, 1, " ", 0, 2, 'C')

	pdf.cell(0, 3, ' ', 0, 2, 'C')
	for r in range(len(scoreOwasp)):
		pdf.cell(30, 5, "Il y a eu " + str(scoreOwasp[r][1]) + " alerte(s) de niveau " + str(scoreOwasp[r][0]) + ".", 0, 2, "J")
		pdf.cell(90, 1, " ", 0, 2, 'C')

	pdf.cell(0, 3, ' ', 0, 2, 'C')
	for s in range(len(attaques)):
		pdf.cell(100, 5, "L'attaque " + attaques[s][0] + " a été relevé " + str(attaques[s][1]) + " fois.", 0, 2, "J")
		pdf.cell(90, 1, " ", 0, 2, 'C')

	pdf.image('figure_' + date + '.png', x = None, y = None, w = 150, h = 120, type = '', link = '')
	pdf.output('compte_rendu_' + date + '.pdf', 'F')
	

def init():
	while (True):
		try:
 			with open("hebdo.sh"): pass

		except IOError:
			username = str(input("Nom d'utilisateur\n>>> "))
			password = str(input("Mot de passe\n>>> "))
			ip_addr = str(input("Adresse IP du serveur où se trouve Kibana\n>>> "))
			authent = base64.b64encode((username + ':' + password).encode())
			authent = authent.decode()
			version = str(input("Version de kibana (ex: 5.6.16)\n>>> "))
			print('''#\t--> Recap
#\t--> Username  : '''+ username +'''
#\t--> Password  : '''+ password +'''
#\t--> IpServeur : '''+ ip_addr +'''
#\t--> Kbn-vrs°  : '''+ version +'''
''')
			rep = str(input("Est-ce correct ?(Y/y/o | N/n)\n>>> "))
			if rep in ["Y","y","o","Yes","Oui"]:
				config_file(ip_addr, authent, version)

		stats_a()
		stats_b()
		rendu()
		break
		
	else:
		False

if __name__ == "__main__":
	init()
