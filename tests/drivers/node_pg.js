const {Client}=require('pg');
(async()=>{const c=new Client({connectionString:'postgresql://postgres:faultwall-demo@127.0.0.1:6433/demo?sslmode=disable',application_name:'agent:node-pg:mission:default'});
await c.connect(); for(let i=1;i<=10;i++) await c.query({name:'q',text:'select id from orders where id=$1',values:[i]});
await c.query('BEGIN'); try{await c.query('select 1/0')}catch(e){} await c.query('ROLLBACK'); await c.end(); console.log('node-pg PASS')})().catch(e=>{console.log('node-pg FAIL',e.message);process.exit(1)});
