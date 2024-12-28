

git clone https://github.com/ANSSI-FR/orc2timeline.git
cd orc2timeline
pip install .

confPath=$(orc2timeline show_conf_file | cut -d':' -f2-)
echo $confPath  >&2
cd ../
mv orc2timeline.yaml $confPath

confPath=$(orc2timeline show_conf)
echo $confPath  >&2

