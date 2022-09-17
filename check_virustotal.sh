signed_monero_zip="monero-gui-v0.18.1.0"
monero_zip="monero-gui-win-x64-v0.18.1.0"
feather_exe="FeatherWalletSetup-2.1.0.exe"
vtotal_apikey="hunter2"
vtotal_endpoint="https://www.virustotal.com/api/v3/"
mkdir signed
mkdir orig 

unzip "${signed_monero_zip}.zip" -d signed
unzip "${monero_zip}.zip" -d orig

upload_file() {
    f="$1"
    upload_url=$(curl -s --request GET --url "${vtotal_endpoint}files/upload_url" --header "x-apikey: $vtotal_apikey" | jq -r .data)
    curl -s --request POST --url "$upload_url" --header "x-apikey: $vtotal_apikey" --form "file=@$f"
}

get_analysis() {
    fid="$1"
    curl -s --request GET --url "${vtotal_endpoint}analyses/$fid" --header "x-apikey: $vtotal_apikey"
}	

get_ids() {
	declare -n array="$2"
	declare -n hashes="$3"
	folder="$1"
	for f in $(find "$folder" -name '*.exe'); do
		then=$(date +%s)
		id=$(upload_file $f | jq -r .data.id)
		echo "${id} ${f}"
		#get filename from path
		basename "$f"
		fname="$(basename -- $f)"
		#get hash
		hash=($(sha256sum ${f}))
		hashes+=(["$fname"]=${hash})
		array+=(["$fname"]=${id})
		now=$(date +%s)
		now=$((${now}-${then}))
		wait=15
		((wait-=$now))
		if [ $wait -lt 0 ]; then
			wait=0
		fi
		sleep $wait
	done
}

declare -A a_orig
declare -A a_signed

declare -A hashes_orig
declare -A hashes_signed

get_ids orig a_orig hashes_orig
get_ids signed a_signed hashes_signed


echo "| Filename | non-signed | signed |"
echo "| --- | --- | --- |"

sleep 15
#1 api call every 15 seconds

for key in "${!a_orig[@]}"; do
	then=$(date +%s)
	#signed will have the same keys as orig
    id_orig=${a_orig[$key]}
	get_stats=$(get_analysis $id_orig)
	sus=$(echo $get_stats | jq -r .data.attributes.stats.suspicious)
	mal=$(echo $get_stats | jq -r .data.attributes.stats.malicious)
	total_orig=$((sus+=mal))
	id_signed=${a_signed[$key]}
	get_stats=$(get_analysis $id_signed)
	sus=$(echo $get_stats | jq -r .data.attributes.stats.suspicious)
	mal=$(echo $get_stats | jq -r .data.attributes.stats.malicious)
	total_signed=$((sus+=mal))
	h_orig="${hashes_orig[$key]}"
	h_sig="${hashes_signed[$key]}"
	echo "| $key | [$total_orig](https://www.virustotal.com/gui/file/${h_orig}/detection) | [${total_signed}](https://www.virustotal.com/gui/file/${h_sig}/detection) |"
	wait=30
	((wait-=$now))
	if [ $wait -lt 0 ]; then
		wait=0
	fi
	sleep $wait
done
