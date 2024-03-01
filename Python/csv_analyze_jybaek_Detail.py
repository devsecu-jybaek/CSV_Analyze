import csv
import re
import pandas as pd
import numpy as np
import tkinter as tk
from tkinter import filedialog

# 최종 수정일자: 2024-02-10
# Version : 1.5.0
# update : 

# CSV 파일 경로 지정(기존코드)
window = tk.Tk()
window.withdraw() # withdraw :기본창을 보이지 않게 하는 함수
window.file = filedialog.askopenfile()
window.mainloop

# CSV 파일 불러오기
df = pd.read_csv(window.file.name, encoding='CP949')


# 분류할 열 지정
col_nm_1 = '출발지IP'
col_nm_2 = '목적지IP'
col_nm_2_2 = '장비IP'
col_nm_3 = '공격명'
col_nm_4 = '출발지 국가'
col_nm_5 = '위험도'
col_nm_6 = 'url'
col_nm_7 = 'Action'

# 위험도 카테고리 결측치 및 이상치 값치환
df.loc[df[col_nm_5] == "1", col_nm_5] = 'High'
df.loc[df[col_nm_5] == "2", col_nm_5] = 'Middle'
df.loc[df[col_nm_5].isnull(), col_nm_5] = 'Info'

# 항목별 데이터 조회 후 프레임화(일반보고서)
top_src_ip_20 = df.loc[:,col_nm_1].value_counts(dropna = False).head(20)
top_dstn_ip_20 = df.loc[:,[col_nm_2_2,col_nm_2]].value_counts(dropna = False).head(20)
top_attack_20 = df.loc[:,col_nm_3].value_counts(dropna = False).head(20)
top_src_country_20 = df.loc[:,col_nm_4].value_counts(dropna = False).head(20)
top_sev_level_20 = df.loc[:,col_nm_5].value_counts(dropna = False).head(20)


# 항목별 데이터 조회 후 프레임화(Detail보고서)
try:
    top_attack_url_sev_level_200 = df.loc[:,[col_nm_3,col_nm_6,col_nm_5,col_nm_7]].value_counts(dropna = False)
except:
    col_nm_6 = 'url_p'
    top_attack_url_sev_level_200 = df.loc[:,[col_nm_3,col_nm_6,col_nm_5,col_nm_7]].value_counts(dropna = False)

top_url_20 = df.loc[:,col_nm_6].value_counts(dropna = False).head(100)
top_src_ip_src_country_20 = df.loc[:,[col_nm_1,col_nm_4]].value_counts(dropna = False).head(100)
top_dstn_ip_20 = df.loc[:,[col_nm_2_2,col_nm_2]].value_counts(dropna = False).head(100)
top_attack_sev_level_20 = df.loc[:,[col_nm_5,col_nm_3]].value_counts(dropna = False)

# 파일명에 데이터갯수를 포함시키기 위한 변수 설정
data_number = df.loc[:,col_nm_5].size

# 조회된 데이터를 기준으로 새로운 프레임 생성 후 인덱스 초기화(Default)
total_1 = pd.DataFrame(top_src_ip_20)
total_1.reset_index(drop =False, inplace = True)

total_2 = pd.DataFrame(top_dstn_ip_20)
total_2.reset_index(drop =False, inplace = True)

total_3 = pd.DataFrame(top_attack_20)
total_3.reset_index(drop =False, inplace = True)

total_4 = pd.DataFrame(top_src_country_20)
total_4.reset_index(drop =False, inplace = True)

total_5 = pd.DataFrame(top_sev_level_20)
total_5.reset_index(drop =False, inplace = True)


# 정렬을 위한 카테고리 생성
attack_category = total_3[col_nm_3].dropna().tolist()
sev_level_category = total_5[col_nm_5].dropna().tolist()


# 조회된 데이터를 기준으로 새로운 프레임 생성 후 인덱스 초기화(Detail)
total_6 = pd.DataFrame(top_attack_url_sev_level_200)
total_6.reset_index(drop =False, inplace = True)

total_7 = pd.DataFrame(top_url_20)
total_7.reset_index(drop =False, inplace = True)

total_8 = pd.DataFrame(top_src_ip_src_country_20)
total_8.reset_index(drop =False, inplace = True)

total_9 = pd.DataFrame(top_dstn_ip_20)
total_9.reset_index(drop =False, inplace = True)

total_10 = pd.DataFrame(top_attack_sev_level_20)
total_10.reset_index(drop =False, inplace = True)

# 복합 분석 시 TOP 3 데이터 추출을 위한 카테고리 함수를 이용한 정렬 및 그룹화 작업
total_6[col_nm_3] = pd.Categorical(total_6[col_nm_3], categories=attack_category, ordered=True)
total_6_sort = total_6.sort_values(by=[col_nm_3,"count"], ascending=[True,False]).groupby(col_nm_3, observed=True).head(3)
total_6_top = pd.DataFrame(total_6_sort)
total_6_top.reset_index(drop =False, inplace = True)
total_6_top = total_6_top.drop('index',axis=1)
total_6_top['count'] = total_6_top['count'].apply(lambda int_num : '{:,}'.format(int_num))

total_10[col_nm_5] = pd.Categorical(total_10[col_nm_5], categories=sev_level_category, ordered=True)

total_10[col_nm_3].replace('',np.nan,inplace=True) # 공격명이 비어있는 행 nan 값으로 치환
total_10.dropna(subset=[col_nm_3],inplace=True) # 공격명이 비어있는 행 제거
total_10_sort = total_10.sort_values(by=[col_nm_5,"count"], ascending=[True,False]).groupby(col_nm_5, observed=True).head(3)
total_10_top = pd.DataFrame(total_10_sort)
total_10_top.reset_index(drop =False, inplace = True)
total_10_top = total_10_top.drop('index',axis=1)
total_10_top['count'] = total_10_top['count'].apply(lambda int_num : '{:,}'.format(int_num))


#데이터프레임에서 Count 열의 데이터에 천단위 구분기호(,) 일괄 적용 / 계산 오류로 인해 복합 분석 후에 적용
total_dfs = []
for i in range(1, 11):
    df_name = f'total_{i}'
    df_n = globals()[df_name]
    total_dfs.append(df_n)

for df_n in total_dfs:
    df_n['count'] = df_n['count'].apply(lambda int_num : '{:,}'.format(int_num))



# 데이터 통합용 목적지 IP, count 틀만 존재하는 빈 프레임 생성
total_2_2 = pd.DataFrame(columns=['목적지IP','count'])

# 생성된 프레임들을 병합
total = pd.concat([total_1,total_2,total_2_2,total_3,total_4,total_5],axis=1)
total_detail = pd.concat([total_6_top,total_7,total_8,total_9,total_10_top],axis=1)

# 각 프레임 구분을 위해 기본 인덱스 이름 변경 및 빈열 & 인덱스 중복 추가
idx_default= [f"{i}위" for i in range(1, 21)]
idx_100= [f"{i}위" for i in range(1, 101)] # TOP3 구현시 개체 수에 따른 조정 필요성에 의해 인덱스를 100개로 임의 설정

total.index = idx_default
total.insert(2, "", "", allow_duplicates=True)
total.insert(3, "", idx_default, allow_duplicates=True)

total.insert(7, "", "", allow_duplicates=True)
total.insert(8, "", idx_default, allow_duplicates=True)

total.insert(11, "", "", allow_duplicates=True)
total.insert(12, "", idx_default, allow_duplicates=True)

total.insert(15, "", "", allow_duplicates=True)
total.insert(16, "", idx_default, allow_duplicates=True)

total.insert(19, "", "", allow_duplicates=True)
total.insert(20, "", idx_default, allow_duplicates=True)


total_detail.index = idx_100
total_detail.insert(5, "", "", allow_duplicates=True)
total_detail.insert(6, "", idx_100, allow_duplicates=True)

total_detail.insert(9, "", "", allow_duplicates=True)
total_detail.insert(10, "", idx_100, allow_duplicates=True)

total_detail.insert(14, "", "", allow_duplicates=True)
total_detail.insert(15, "", idx_100, allow_duplicates=True)

total_detail.insert(19, "", "", allow_duplicates=True)
total_detail.insert(20, "", idx_100, allow_duplicates=True)



log_nm = str(window.file.name).split('/') #기본파일명

#파일명변환과정
log_fl = log_nm[-1].split('LOG')

log_file_name = log_fl[0]

free_name = re.sub(r"[^a-zA-Z]", "", log_file_name)+'_'+re.sub(r"[^가-힣]", "", log_file_name)+'_'
eqp_name = free_name.replace('waf','').replace('ids','').replace('통합','').replace('_','').replace('WAF','').replace('IDS','')

if log_file_name.rfind('통합') > 0 :
    result_csv_file = eqp_name+'_통합_'+'top_20[data_'+str(data_number)+'].csv'
elif log_file_name.rfind('WAF') > 0 or log_file_name.rfind('waf') > 0 :
    result_csv_file = eqp_name+'_WAF_'+'top_20[data_'+str(data_number)+'].csv'
elif log_file_name.rfind('IDS') > 0 or log_file_name.rfind('ids') > 0 :
    result_csv_file = eqp_name+'_IDS_'+'top_20[data_'+str(data_number)+'].csv'
else :
    result_csv_file = eqp_name +'차트데이터용_top_20_분석[data_'+str(data_number)+'].csv'

result_csv_file_detail = eqp_name +'한글보고서용_상세분석_[data_'+str(data_number)+'].csv'


# 분석 결과를 CSV 파일로 저장
total.to_csv('./../'+result_csv_file, header=True, encoding='utf-8-sig', index=True)
total_detail.to_csv('./../'+result_csv_file_detail, header=True, encoding='utf-8-sig', index=True)

