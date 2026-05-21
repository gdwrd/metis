get '/profiles/:id', to: 'profiles#show'

def show
  raw(params[:id])
end

get '/sinatra/:id'
def sinatra
  system(params[:cmd])
end
