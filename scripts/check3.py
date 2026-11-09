import pandas as pd, numpy as np
pd.set_option('display.width',250); pd.set_option('display.max_columns',40); pd.set_option('display.max_rows',500)
log=pd.read_csv('dataset/Attack_log-20261109T113913Z-1-001/Attack_log/attack_log.csv')
cols=['Src IP','Dst IP','Protocol','Timestamp','Flow Duration','Total Fwd Packet','Total Length of Fwd Packet','Dst Port','Src Port']
df=pd.concat([pd.read_csv('dataset/csv/sesi%d_all.csv/sesi%d_all.csv'%(s,s),usecols=cols) for s in (1,2,3)],ignore_index=True)
df['t']=pd.to_datetime(df['Timestamp'],format='%d/%m/%Y %I:%M:%S %p')
df['ep']=(df['t']-pd.Timestamp('1970-01-01')).dt.total_seconds().astype('int64')
df['min']=df['t'].dt.floor('min')
df['att']=df['Src IP']=='192.168.1.65'
df['inlan']=df['Src IP'].str.startswith('198.51.100.')
g=df.groupby('min')
W=pd.DataFrame({'flows':g.size(),'uSrc':g['Src IP'].nunique(),'uDst':g['Dst IP'].nunique(),'pkts':g['Total Fwd Packet'].sum(),
 'attfl':g['att'].sum(),'extSrc':g.apply(lambda x:(~x.inlan).sum())})
W['t']=W.index
# assign run by window minute start
W['run']='benign'
for _,r in log.iterrows():
    s=pd.Timestamp(r.start_ts,unit='s'); e=pd.Timestamp(r.end_ts,unit='s')
    W.loc[(W.t+pd.Timedelta('60s')>s)&(W.t<=e),'run']=r.run_id
W['kind']=W.run.map(lambda r:'benign' if r=='benign' else ('focused' if r.startswith('F') else ('carpet' if r.startswith('C') else 'test')))
print(W.groupby('kind').size())
print(W.groupby('run')[['flows','uSrc','uDst','pkts','attfl','extSrc']].agg(['count','median']).iloc[:, [0,1,3,5,7,9,11]].to_string())
# first window per run to check edge alignment
print('\nbenign windows stats:'); print(W[W.kind=='benign'][['flows','uSrc','uDst','pkts','attfl','extSrc']].describe().to_string())
# benign: windows with attacker flows (unlogged attack traffic?)
b=W[(W.kind=='benign')&(W.attfl>0)]
print('\nbenign-labeled windows w/ attacker flows:',len(b)); 
print(b[['flows','uSrc','uDst','pkts','attfl']].head(80).to_string())
W.to_csv('windows_tmp.csv')
