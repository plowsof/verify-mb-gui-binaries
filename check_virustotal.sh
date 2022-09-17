signed_monero_zip="monero-gui-v0.18.1.0"
monero_zip="monero-gui-win-x64-v0.18.1.0"
feather_exe="FeatherWalletSetup-2.1.0.exe"
vtotal_apikey="hunter2"
vtotal_endpoint="https://www.virustotal.com/api/v3/"

mkdir signed
mkdir orig 

#unzip "${signed_monero_zip}.zip" -d signed
#unzip "${monero_zip}.zip" -d orig

#if the file exists dont upload, just grab hits
check_exists() {
	hash="$1"
	then=$(date +%s)
	curl -s --request GET --url "${vtotal_endpoint}search?query=$hash" --header "x-apikey: $vtotal_apikey"
	now=$(date +%s)
	now=$((${now}-${then}))
	wait=15
	((wait-=$now))
	if [ $wait -lt 0 ]; then
		wait=0
	fi
	sleep $wait
}

upload_file() {
	f="$1"
	hash=($(sha256sum ${f}))
	data=$(check_exists $hash)
	if [ $(echo $data | jq -r .data[].arrtibutes) ]; then
		#echo $data
		sus=$(echo $data | jq -r .data[].attributes.last_analysis_stats.suspicious)
		mal=$(echo $data | jq -r .data[].attributes.last_analysis_stats.malicious)
		total=$((sus+=mal))
		existing_hash+=([$hash]=$total)
	else
		#we dont exist
		fsize=$(stat -c%s "$f")
		if [[ $fsize -gt 33554431 ]]; then
			upload_bigfile "$f"
		else
			then=$(date +%s)
			curl -s --request POST --url "${vtotal_endpoint}files" --header "x-apikey: $vtotal_apikey" --form "file=@$f"
			now=$(date +%s)
			now=$((${now}-${then}))
			wait=15
			((wait-=$now))
			if [ $wait -lt 0 ]; then
				wait=0
			fi
			sleep $wait
	    fi
	fi
}

upload_bigfile() {
    f="$1"
    then=$(date +%s)
    upload_url=$(curl -s --request GET --url "${vtotal_endpoint}files/upload_url" --header "x-apikey: $vtotal_apikey" | jq -r .data)
    now=$(date +%s)
	now=$((${now}-${then}))
	wait=15
	((wait-=$now))
	if [ $wait -lt 0 ]; then
		wait=0
	fi
	sleep $wait
    then=$(date +%s)
    curl -s --request POST --url "$upload_url" --header "x-apikey: $vtotal_apikey" --form "file=@$f"
	now=$(date +%s)
	now=$((${now}-${then}))
	wait=15
	((wait-=$now))
	if [ $wait -lt 0 ]; then
		wait=0
	fi
	sleep $wait
}

get_analysis() {
    fid="$1"
    then=$(date +%s)
    curl -s --request GET --url "${vtotal_endpoint}analyses/$fid" --header "x-apikey: $vtotal_apikey"
	now=$(date +%s)
	now=$((${now}-${then}))
    wait=15
	((wait-=$now))
	if [ $wait -lt 0 ]; then
		wait=0
	fi
	sleep $wait
}	

get_ids() {
	declare -n array="$2"
	declare -n hashes="$3"
	folder="$1"
	for f in $(find "$folder" -name '*.exe'); do
		id=$(upload_file $f | jq -r .data.id)
		echo $id
		#echo "${id} ${f}"
		#get filename from path
		basename "$f"
		fname="$(basename -- $f)"
		#get hash
		hash=($(sha256sum ${f}))
		#check_exists $hash
		hashes+=(["$fname"]=${hash})
		array+=(["$fname"]=${id})

	done
}

main(){
	declare -A a_orig
	declare -A a_signed

	declare -A hashes_orig
	declare -A hashes_signed

	declare -A existing_hash

	get_ids orig a_orig hashes_orig
	get_ids signed a_signed hashes_signed


	echo "| Filename | non-signed | signed |"
	echo "| --- | --- | --- |"

	#1 api call every 15 seconds

	for key in "${!a_orig[@]}"; do
		#signed will have the same keys as orig
	    id_orig=${a_orig[$key]}
	    h_orig="${hashes_orig[$key]}"
	    if [ existing_hash[$h_orig] ]; then
	    	total_orig=${existing_hash[$h_orig]}
	    else
			get_stats=$(get_analysis $id_orig)
			sus=$(echo $get_stats | jq -r .data.attributes.stats.suspicious)
			mal=$(echo $get_stats | jq -r .data.attributes.stats.malicious)
			total_orig=$((sus+=mal))
	    fi

		id_signed=${a_signed[$key]}
		h_sig="${hashes_signed[$key]}"
	    if [ existing_hash[$h_sig] ]; then
	    	total_signed=${existing_hash[$h_sig]}
	    else
			get_stats=$(get_analysis $id_signed)
			sus=$(echo $get_stats | jq -r .data.attributes.stats.suspicious)
			mal=$(echo $get_stats | jq -r .data.attributes.stats.malicious)
			total_signed=$((sus+=mal))
	    fi	
		echo "| $key | [$total_orig](https://www.virustotal.com/gui/file/${h_orig}/detection) | [${total_signed}](https://www.virustotal.com/gui/file/${h_sig}/detection) |"
	done
}

main
